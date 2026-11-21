use std::sync::{Arc, OnceLock};

use rustc_hash::{FxHashMap, FxHashSet};

use crate::pack::{empty_packfile, finalize_pack, push_pack_obj_header, DecodedObject, PackDecoder};
use crate::sha1::{hex_to_oid, write_oid_hex, ObjKind, ZERO_OID_HEX};
use crate::store::{build_http_response, ForgeStore, PushCommandRef, Repo};

const MAX_SIDEBAND_CHUNK: usize = 65_500;
const PKT_FLUSH: &[u8] = b"0000";
const PKT_DELIM: &[u8] = b"0001";

static UPLOAD_V2_ADV_HTTP: OnceLock<Vec<u8>> = OnceLock::new();

#[inline]
fn write_git_http_header(out: &mut Vec<u8>, content_type: &[u8], body_len: usize) {
    let mut len_buf = itoa::Buffer::new();
    let len_str = len_buf.format(body_len);
    out.reserve(48 + content_type.len() + len_str.len() + body_len);
    out.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Type: ");
    out.extend_from_slice(content_type);
    out.extend_from_slice(b"\r\nContent-Length: ");
    out.extend_from_slice(len_str.as_bytes());
    out.extend_from_slice(b"\r\n\r\n");
}

fn build_git_http_resp(content_type: &[u8], body: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    write_git_http_header(&mut buf, content_type, body.len());
    buf.extend_from_slice(body);
    buf
}

fn upload_v2_adv_http() -> &'static [u8] {
    UPLOAD_V2_ADV_HTTP.get_or_init(|| {
        let mut body = Vec::with_capacity(96);
        push_pkt_line(&mut body, b"version 2\n");
        push_pkt_line(&mut body, b"ls-refs=unborn\n");
        push_pkt_line(&mut body, b"fetch=shallow wait-for-done\n");
        push_pkt_line(&mut body, b"object-format=sha1\n");
        body.extend_from_slice(PKT_FLUSH);
        build_git_http_resp(b"application/x-git-upload-pack-advertisement", &body)
    })
}

#[inline]
fn push_hex4(out: &mut Vec<u8>, val: usize) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(HEX[(val >> 12) & 0xf]);
    out.push(HEX[(val >> 8) & 0xf]);
    out.push(HEX[(val >> 4) & 0xf]);
    out.push(HEX[val & 0xf]);
}

#[inline]
fn push_pkt_line(out: &mut Vec<u8>, payload: &[u8]) {
    let total = payload.len() + 4;
    push_hex4(out, total);
    out.extend_from_slice(payload);
}

#[derive(Clone, Copy)]
enum PktItem<'a> {
    Flush,
    Delim,
    Line(&'a [u8]),
}

fn parse_pkt_stream<'a>(buf: &'a [u8]) -> Result<(Vec<PktItem<'a>>, &'a [u8]), String> {
    let mut items = Vec::with_capacity(32);
    let mut pos = 0usize;
    while pos < buf.len() {
        if pos + 4 > buf.len() {
            return Err("Truncated pkt-line header".to_string());
        }
        let hex = std::str::from_utf8(&buf[pos..pos + 4])
            .map_err(|_| "Invalid pkt-line header".to_string())?;
        let len = u16::from_str_radix(hex, 16)
            .map_err(|_| format!("Invalid pkt-line length {hex}"))? as usize;
        pos += 4;
        if len == 0 {
            items.push(PktItem::Flush);
            if pos + 4 <= buf.len() && &buf[pos..pos + 4] == b"PACK" {
                return Ok((items, &buf[pos..]));
            }
            continue;
        }
        if len == 1 {
            items.push(PktItem::Delim);
            continue;
        }
        if len == 2 {
            continue;
        }
        if len < 4 || pos + (len - 4) > buf.len() {
            return Err("Truncated pkt-line payload".to_string());
        }
        items.push(PktItem::Line(&buf[pos..pos + (len - 4)]));
        pos += len - 4;
    }
    Ok((items, &[][..]))
}

fn wrap_sideband_64k(out: &mut Vec<u8>, payload: &[u8]) {
    let mut offset = 0usize;
    while offset < payload.len() {
        let end = (offset + MAX_SIDEBAND_CHUNK).min(payload.len());
        let slice = &payload[offset..end];
        let total = slice.len() + 5;
        push_hex4(out, total);
        out.push(0x01);
        out.extend_from_slice(slice);
        offset = end;
    }
}

#[inline]
fn parse_hex4(b: &[u8]) -> Option<usize> {
    if b.len() < 4 {
        return None;
    }
    let mut v = 0usize;
    for &c in &b[..4] {
        let d = match c {
            b'0'..=b'9' => (c - b'0') as usize,
            b'a'..=b'f' => (c - b'a' + 10) as usize,
            b'A'..=b'F' => (c - b'A' + 10) as usize,
            _ => return None,
        };
        v = (v << 4) | d;
    }
    Some(v)
}

fn parse_receive_pack_request<'a>(
    buf: &'a [u8],
) -> Result<(Vec<PushCommandRef<'a>>, bool, &'a [u8]), String> {
    let mut commands = Vec::with_capacity(4);
    let mut use_sideband = false;
    let mut pos = 0usize;
    while pos < buf.len() {
        if pos + 4 > buf.len() {
            return Err("Truncated pkt-line header".to_string());
        }
        let Some(len) = parse_hex4(&buf[pos..pos + 4]) else {
            return Err("Invalid pkt-line header".to_string());
        };
        pos += 4;
        if len == 0 {
            if pos + 4 <= buf.len() && &buf[pos..pos + 4] == b"PACK" {
                return Ok((commands, use_sideband, &buf[pos..]));
            }
            continue;
        }
        if len == 1 || len == 2 {
            continue;
        }
        if len < 4 || pos + (len - 4) > buf.len() {
            return Err("Truncated pkt-line payload".to_string());
        }
        let raw = &buf[pos..pos + (len - 4)];
        pos += len - 4;

        let (main_raw, cap_opt) = match memchr::memchr(0, raw) {
            Some(idx) => (&raw[..idx], Some(&raw[idx + 1..])),
            None => (raw, None),
        };
        if let Some(cap_bytes) = cap_opt {
            for cap in cap_bytes.trim_ascii().split(|&b| b == b' ') {
                if cap == b"side-band-64k" || cap == b"side-band" {
                    use_sideband = true;
                }
            }
        }
        let main_trimmed = main_raw.strip_suffix(b"\n").unwrap_or(main_raw);
        let mut parts = main_trimmed.splitn(3, |&b| b == b' ');
        let (Some(old_b), Some(new_b), Some(ref_b)) = (parts.next(), parts.next(), parts.next()) else {
            return Err("Malformed receive-pack command line".to_string());
        };
        let (Some(old_oid), Some(new_oid), Ok(ref_name)) = (
            hex_to_oid(old_b),
            hex_to_oid(new_b),
            std::str::from_utf8(ref_b),
        ) else {
            return Err("Malformed receive-pack command line".to_string());
        };
        commands.push(PushCommandRef {
            old_oid,
            new_oid,
            ref_name,
        });
    }
    Ok((commands, use_sideband, &[][..]))
}

fn build_upload_v0_http(repo: &Repo) -> Arc<Vec<u8>> {
    let head_ref = repo.head_ref_name();
    let caps = format!(
        "multi_ack_detailed side-band-64k thin-pack ofs-delta shallow no-progress include-tag symref=HEAD:{head_ref} agent=makefun-forge/1.0"
    );
    let mut body = Vec::with_capacity(512);
    push_pkt_line(&mut body, b"# service=git-upload-pack\n");
    body.extend_from_slice(PKT_FLUSH);

    if repo.refs.is_empty() {
        let mut line = Vec::with_capacity(128 + caps.len());
        line.extend_from_slice(ZERO_OID_HEX.as_bytes());
        line.extend_from_slice(b" capabilities^{}\0");
        line.extend_from_slice(caps.as_bytes());
        line.push(b'\n');
        push_pkt_line(&mut body, &line);
        body.extend_from_slice(PKT_FLUSH);
    } else {
        let head_tip = repo
            .refs
            .get(&head_ref)
            .copied()
            .unwrap_or_else(|| *repo.refs.values().next().unwrap());
        let mut caps_opt: Option<&[u8]> = Some(caps.as_bytes());
        let emit_ref = |body: &mut Vec<u8>, oid: &[u8; 20], name: &[u8], caps_opt: &mut Option<&[u8]>| {
            let cap_slice = caps_opt.take();
            let mut line = Vec::with_capacity(64 + name.len() + cap_slice.map(|c| c.len()).unwrap_or(0));
            write_oid_hex(&mut line, oid);
            line.push(b' ');
            line.extend_from_slice(name);
            if let Some(c) = cap_slice {
                line.push(0);
                line.extend_from_slice(c);
            }
            line.push(b'\n');
            push_pkt_line(body, &line);
        };
        emit_ref(&mut body, &head_tip, b"HEAD", &mut caps_opt);
        for (name, oid) in &repo.refs {
            emit_ref(&mut body, oid, name.as_bytes(), &mut caps_opt);
            if let Some(peeled) = repo.peel_tag(oid) {
                let mut line = Vec::with_capacity(48 + name.len());
                write_oid_hex(&mut line, &peeled);
                line.push(b' ');
                line.extend_from_slice(name.as_bytes());
                line.extend_from_slice(b"^{}\n");
                push_pkt_line(&mut body, &line);
            }
        }
        body.extend_from_slice(PKT_FLUSH);
    }
    Arc::new(build_git_http_resp(
        b"application/x-git-upload-pack-advertisement",
        &body,
    ))
}

fn build_receive_v0_http(repo: &Repo) -> Arc<Vec<u8>> {
    const SERVICE_PREAMBLE: &[u8] = b"001f# service=git-receive-pack\n0000";
    const CAPS: &[u8] = b"report-status side-band-64k delete-refs ofs-delta";

    let body_len = if repo.refs.is_empty() {
        SERVICE_PREAMBLE.len() + (4 + 40 + 1 + 15 + 1 + CAPS.len() + 1) + 4
    } else {
        let mut len = SERVICE_PREAMBLE.len() + 4;
        let mut first = true;
        for name in repo.refs.keys() {
            len += 4 + 40 + 1 + name.len() + if first { 1 + CAPS.len() } else { 0 } + 1;
            first = false;
        }
        len
    };

    let mut out = Vec::new();
    write_git_http_header(
        &mut out,
        b"application/x-git-receive-pack-advertisement",
        body_len,
    );
    out.extend_from_slice(SERVICE_PREAMBLE);

    if repo.refs.is_empty() {
        let pkt_len = 4 + 40 + 1 + 15 + 1 + CAPS.len() + 1;
        push_hex4(&mut out, pkt_len);
        out.extend_from_slice(ZERO_OID_HEX.as_bytes());
        out.extend_from_slice(b" capabilities^{}\0");
        out.extend_from_slice(CAPS);
        out.push(b'\n');
    } else {
        let mut first = true;
        for (name, oid) in &repo.refs {
            let pkt_len = 4 + 40 + 1 + name.len() + if first { 1 + CAPS.len() } else { 0 } + 1;
            push_hex4(&mut out, pkt_len);
            write_oid_hex(&mut out, oid);
            out.push(b' ');
            out.extend_from_slice(name.as_bytes());
            if first {
                out.push(0);
                out.extend_from_slice(CAPS);
                first = false;
            }
            out.push(b'\n');
        }
    }
    out.extend_from_slice(PKT_FLUSH);
    Arc::new(out)
}

fn collect_tree_and_blobs(
    repo: &Repo,
    tree_oid: &[u8; 20],
    excluded: &FxHashSet<[u8; 20]>,
    out: &mut FxHashMap<[u8; 20], ()>,
) {
    if excluded.contains(tree_oid) || out.contains_key(tree_oid) {
        return;
    }
    let Some(tree_obj) = repo.objects.get(tree_oid) else {
        return;
    };
    if tree_obj.kind != ObjKind::Tree {
        return;
    }
    out.insert(*tree_oid, ());

    let data = &tree_obj.data;
    let mut pos = 0usize;
    while pos < data.len() {
        let Some(sp_rel) = memchr::memchr(b' ', &data[pos..]) else {
            break;
        };
        let sp = pos + sp_rel;
        let Some(nul_rel) = memchr::memchr(0, &data[sp + 1..]) else {
            break;
        };
        let nul = sp + 1 + nul_rel;
        if nul + 21 > data.len() {
            break;
        }
        let mode = &data[pos..sp];
        let mut oid = [0u8; 20];
        oid.copy_from_slice(&data[nul + 1..nul + 21]);
        pos = nul + 21;
        if mode == b"40000" || mode == b"040000" {
            collect_tree_and_blobs(repo, &oid, excluded, out);
        } else if !excluded.contains(&oid) && !out.contains_key(&oid) && repo.objects.contains_key(&oid) {
            out.insert(oid, ());
        }
    }
}

struct FetchPlan {
    shallow: Vec<[u8; 20]>,
    unshallow: Vec<[u8; 20]>,
    pack: Vec<u8>,
}

fn compute_fetch_plan(
    repo: &Repo,
    wants: &[[u8; 20]],
    haves: &[[u8; 20]],
    shallows: &[[u8; 20]],
    depth: Option<usize>,
) -> FetchPlan {
    let client_shallows: FxHashSet<[u8; 20]> = shallows.iter().copied().collect();
    let have_set: FxHashSet<[u8; 20]> = haves.iter().copied().collect();
    let mut excluded: FxHashSet<[u8; 20]> = FxHashSet::default();

    let mut have_q: Vec<[u8; 20]> = haves.to_vec();
    let mut visited_haves: FxHashSet<[u8; 20]> = FxHashSet::default();
    let mut dummy_map: FxHashMap<[u8; 20], ()> = FxHashMap::default();
    while let Some(oid) = have_q.pop() {
        if !visited_haves.insert(oid) {
            continue;
        }
        let Some(obj) = repo.objects.get(&oid) else {
            continue;
        };
        if obj.kind == ObjKind::Tag {
            excluded.insert(oid);
            if let Some(t) = obj.tag_target {
                have_q.push(t);
            }
            continue;
        }
        if obj.kind == ObjKind::Commit {
            excluded.insert(oid);
            if let Some(tree_oid) = obj.tree_oid {
                dummy_map.clear();
                collect_tree_and_blobs(repo, &tree_oid, &excluded, &mut dummy_map);
                for k in dummy_map.keys() {
                    excluded.insert(*k);
                }
            }
            if !client_shallows.contains(&oid) {
                for &p in &obj.parents {
                    if !visited_haves.contains(&p) {
                        have_q.push(p);
                    }
                }
            }
        }
    }

    let mut objects_map: FxHashMap<[u8; 20], ()> = FxHashMap::default();
    let mut commit_tips = Vec::new();
    for &w in wants {
        let mut cur = w;
        for _ in 0..8 {
            let Some(obj) = repo.objects.get(&cur) else {
                break;
            };
            if obj.kind == ObjKind::Tag {
                if !excluded.contains(&cur) {
                    objects_map.insert(cur, ());
                }
                match obj.tag_target {
                    Some(t) => cur = t,
                    None => break,
                }
            } else {
                if obj.kind == ObjKind::Commit {
                    commit_tips.push(cur);
                } else if !excluded.contains(&cur) {
                    objects_map.insert(cur, ());
                }
                break;
            }
        }
    }

    let mut shallow_out = Vec::new();
    let mut unshallow_out = Vec::new();
    let mut included_commits = Vec::new();

    if let Some(max_depth) = depth.filter(|&d| d >= 1) {
        let mut min_depth: FxHashMap<[u8; 20], usize> = FxHashMap::default();
        let mut queue = std::collections::VecDeque::new();
        for tip in commit_tips {
            if !min_depth.contains_key(&tip) {
                min_depth.insert(tip, 1);
                queue.push_back((tip, 1usize));
            }
        }
        let mut shallow_marks: FxHashSet<[u8; 20]> = FxHashSet::default();
        let mut unshallow_marks: FxHashSet<[u8; 20]> = FxHashSet::default();
        while let Some((oid, d)) = queue.pop_front() {
            let Some(obj) = repo.objects.get(&oid) else {
                continue;
            };
            if obj.kind != ObjKind::Commit {
                continue;
            }
            if !have_set.contains(&oid) && !excluded.contains(&oid) {
                included_commits.push(oid);
            }
            if d >= max_depth {
                if !obj.parents.is_empty() {
                    shallow_marks.insert(oid);
                }
                continue;
            }
            if client_shallows.contains(&oid) && !obj.parents.is_empty() {
                unshallow_marks.insert(oid);
            }
            for &p in &obj.parents {
                let replace = match min_depth.get(&p) {
                    None => true,
                    Some(&prev) => d + 1 < prev,
                };
                if replace {
                    min_depth.insert(p, d + 1);
                    queue.push_back((p, d + 1));
                }
            }
        }
        shallow_out.extend(shallow_marks);
        unshallow_out.extend(unshallow_marks);
    } else {
        let mut visited: FxHashSet<[u8; 20]> = FxHashSet::default();
        let mut stack = commit_tips;
        while let Some(oid) = stack.pop() {
            if !visited.insert(oid) || excluded.contains(&oid) {
                continue;
            }
            let Some(obj) = repo.objects.get(&oid) else {
                continue;
            };
            if obj.kind != ObjKind::Commit {
                continue;
            }
            included_commits.push(oid);
            if client_shallows.contains(&oid) {
                continue;
            }
            for &p in &obj.parents {
                if !visited.contains(&p) && !excluded.contains(&p) {
                    stack.push(p);
                }
            }
        }
    }

    for c_oid in included_commits {
        let Some(c_obj) = repo.objects.get(&c_oid) else {
            continue;
        };
        objects_map.insert(c_oid, ());
        if let Some(tree_oid) = c_obj.tree_oid {
            collect_tree_and_blobs(repo, &tree_oid, &excluded, &mut objects_map);
        }
    }

    let pack = if objects_map.is_empty() {
        empty_packfile()
    } else {
        let mut pack_buf = Vec::with_capacity(objects_map.len() * 128 + 32);
        pack_buf.resize(12, 0);
        let mut count = 0u32;
        for oid in objects_map.keys() {
            if let Some(obj) = repo.objects.get(oid) {
                push_pack_obj_header(&mut pack_buf, obj.kind, obj.data.len());
                pack_buf.extend_from_slice(obj.compressed_bytes());
                count += 1;
            }
        }
        finalize_pack(pack_buf, count)
    };

    FetchPlan {
        shallow: shallow_out,
        unshallow: unshallow_out,
        pack,
    }
}

fn handle_ls_refs(repo: &Repo, lines: &[PktItem<'_>]) -> Vec<u8> {
    let mut want_peel = false;
    let mut want_symrefs = false;
    let mut want_unborn = false;
    let mut prefixes: Vec<&[u8]> = Vec::new();

    for &item in lines {
        let PktItem::Line(raw) = item else { continue };
        let line = raw.strip_suffix(b"\n").unwrap_or(raw);
        if line.is_empty()
            || line.starts_with(b"command=")
            || line.starts_with(b"agent=")
            || line.starts_with(b"object-format=")
        {
            continue;
        }
        if line == b"peel" {
            want_peel = true;
        } else if line == b"symrefs" {
            want_symrefs = true;
        } else if line == b"unborn" {
            want_unborn = true;
        } else if let Some(pref) = line.strip_prefix(b"ref-prefix ") {
            prefixes.push(pref);
        }
    }

    let matches_prefix = |name: &[u8]| -> bool {
        prefixes.is_empty() || prefixes.iter().any(|p| name.starts_with(p))
    };

    let mut body = Vec::with_capacity(512);
    let head_target = repo.head_ref_name();
    if matches_prefix(b"HEAD") {
        if let Some(tip) = repo.refs.get(&head_target) {
            let mut line = Vec::with_capacity(96);
            write_oid_hex(&mut line, tip);
            line.extend_from_slice(b" HEAD");
            if want_symrefs {
                line.extend_from_slice(b" symref-target:");
                line.extend_from_slice(head_target.as_bytes());
            }
            line.push(b'\n');
            push_pkt_line(&mut body, &line);
        } else if want_unborn {
            let mut line = Vec::with_capacity(96);
            line.extend_from_slice(b"unborn HEAD");
            if want_symrefs {
                line.extend_from_slice(b" symref-target:");
                line.extend_from_slice(head_target.as_bytes());
            }
            line.push(b'\n');
            push_pkt_line(&mut body, &line);
        }
    }

    for (name, oid) in &repo.refs {
        if !matches_prefix(name.as_bytes()) {
            continue;
        }
        let mut line = Vec::with_capacity(112);
        write_oid_hex(&mut line, oid);
        line.push(b' ');
        line.extend_from_slice(name.as_bytes());
        if want_peel {
            if let Some(peeled) = repo.peel_tag(oid) {
                line.extend_from_slice(b" peeled:");
                write_oid_hex(&mut line, &peeled);
            }
        }
        line.push(b'\n');
        push_pkt_line(&mut body, &line);
    }

    body.extend_from_slice(PKT_FLUSH);
    build_git_http_resp(b"application/x-git-upload-pack-result", &body)
}

fn parse_oid_arg(slice: &[u8]) -> Option<[u8; 20]> {
    let trimmed = slice.trim_ascii();
    hex_to_oid(trimmed)
}

fn handle_fetch_v2(repo: &Repo, lines: &[PktItem<'_>]) -> Vec<u8> {
    let mut wants = Vec::new();
    let mut haves = Vec::new();
    let mut shallows = Vec::new();
    let mut depth: Option<usize> = None;
    let mut done = false;

    for &item in lines {
        let PktItem::Line(raw) = item else { continue };
        let line = raw.strip_suffix(b"\n").unwrap_or(raw);
        if let Some(rest) = line.strip_prefix(b"want ") {
            if let Some(oid) = parse_oid_arg(rest) {
                wants.push(oid);
            }
        } else if let Some(rest) = line.strip_prefix(b"have ") {
            if let Some(oid) = parse_oid_arg(rest) {
                haves.push(oid);
            }
        } else if let Some(rest) = line.strip_prefix(b"shallow ") {
            if let Some(oid) = parse_oid_arg(rest) {
                shallows.push(oid);
            }
        } else if let Some(rest) = line.strip_prefix(b"deepen ") {
            if let Ok(s) = std::str::from_utf8(rest.trim_ascii()) {
                depth = s.parse::<usize>().ok();
            }
        } else if line == b"done" {
            done = true;
        }
    }

    if !done {
        let mut body = Vec::with_capacity(64);
        push_pkt_line(&mut body, b"acknowledgments\n");
        push_pkt_line(&mut body, b"NAK\n");
        body.extend_from_slice(PKT_FLUSH);
        return build_git_http_resp(b"application/x-git-upload-pack-result", &body);
    }

    let plan = compute_fetch_plan(repo, &wants, &haves, &shallows, depth);
    let mut body = Vec::with_capacity(plan.pack.len() + 256);
    if !plan.shallow.is_empty() || !plan.unshallow.is_empty() {
        push_pkt_line(&mut body, b"shallow-info\n");
        for s in &plan.shallow {
            let mut l = Vec::with_capacity(50);
            l.extend_from_slice(b"shallow ");
            write_oid_hex(&mut l, s);
            l.push(b'\n');
            push_pkt_line(&mut body, &l);
        }
        for u in &plan.unshallow {
            let mut l = Vec::with_capacity(52);
            l.extend_from_slice(b"unshallow ");
            write_oid_hex(&mut l, u);
            l.push(b'\n');
            push_pkt_line(&mut body, &l);
        }
        body.extend_from_slice(PKT_DELIM);
    }

    push_pkt_line(&mut body, b"packfile\n");
    wrap_sideband_64k(&mut body, &plan.pack);
    body.extend_from_slice(PKT_FLUSH);
    build_git_http_resp(b"application/x-git-upload-pack-result", &body)
}

fn handle_fetch_v0(repo: &Repo, lines: &[PktItem<'_>]) -> Vec<u8> {
    let mut wants = Vec::new();
    let mut haves = Vec::new();
    let mut shallows = Vec::new();
    let mut depth: Option<usize> = None;
    let mut use_sideband = false;

    for &item in lines {
        let PktItem::Line(raw) = item else { continue };
        let line = raw.strip_suffix(b"\n").unwrap_or(raw);
        if let Some(rest) = line.strip_prefix(b"want ") {
            let mut parts = rest.trim_ascii().split(|&b| b == b' ');
            if let Some(first) = parts.next() {
                if let Some(oid) = hex_to_oid(first) {
                    wants.push(oid);
                }
            }
            for cap in parts {
                if cap == b"side-band-64k" || cap == b"side-band" {
                    use_sideband = true;
                }
            }
        } else if let Some(rest) = line.strip_prefix(b"have ") {
            if let Some(oid) = parse_oid_arg(rest) {
                haves.push(oid);
            }
        } else if let Some(rest) = line.strip_prefix(b"shallow ") {
            if let Some(oid) = parse_oid_arg(rest) {
                shallows.push(oid);
            }
        } else if let Some(rest) = line.strip_prefix(b"deepen ") {
            if let Ok(s) = std::str::from_utf8(rest.trim_ascii()) {
                depth = s.parse::<usize>().ok();
            }
        }
    }

    let plan = compute_fetch_plan(repo, &wants, &haves, &shallows, depth);
    let mut body = Vec::with_capacity(plan.pack.len() + 256);
    for s in &plan.shallow {
        let mut l = Vec::with_capacity(50);
        l.extend_from_slice(b"shallow ");
        write_oid_hex(&mut l, s);
        l.push(b'\n');
        push_pkt_line(&mut body, &l);
    }
    for u in &plan.unshallow {
        let mut l = Vec::with_capacity(52);
        l.extend_from_slice(b"unshallow ");
        write_oid_hex(&mut l, u);
        l.push(b'\n');
        push_pkt_line(&mut body, &l);
    }
    push_pkt_line(&mut body, b"NAK\n");
    if use_sideband {
        wrap_sideband_64k(&mut body, &plan.pack);
        body.extend_from_slice(PKT_FLUSH);
    } else {
        body.extend_from_slice(&plan.pack);
    }
    build_git_http_resp(b"application/x-git-upload-pack-result", &body)
}

fn write_json_err_into(write_buf: &mut Vec<u8>, status: u16, msg: &str) {
    let status_line: &[u8] = match status {
        400 => b"HTTP/1.1 400 Bad Request",
        404 => b"HTTP/1.1 404 Not Found",
        _ => b"HTTP/1.1 500 Internal Server Error",
    };
    let mut body = Vec::with_capacity(msg.len() + 32);
    body.extend_from_slice(b"{\"message\":");
    crate::store::json_escape_into(&mut body, msg);
    body.push(b'}');
    let full = build_http_response(status_line, b"application/json; charset=utf-8", b"", &body);
    write_buf.extend_from_slice(&full);
}

fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle.as_bytes()))
}

fn query_get<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return Some(v);
            }
        }
    }
    None
}

pub enum GitResponse {
    Static(&'static [u8]),
    Cached(Arc<Vec<u8>>),
    PushWritten {
        updated_receive_adv: Option<(Arc<Vec<u8>>, u64)>,
    },
    Written,
}

/// Dispatch `/{owner}/{repo}.git/...` requests. Returns `None` if route doesn't match `.git/`.
pub fn try_handle_git_http(
    store: &ForgeStore,
    decoder: &mut PackDecoder,
    method: &str,
    pathname: &str,
    query: &str,
    git_protocol_header: Option<&str>,
    body: &[u8],
    write_buf: &mut Vec<u8>,
) -> Option<GitResponse> {
    let git_idx = pathname.find(".git/")?;
    if git_idx <= 1 {
        return None;
    }
    let repo_seg = &pathname[1..git_idx];
    let slash = repo_seg.find('/')?;
    if repo_seg[slash + 1..].contains('/') {
        return None;
    }
    let owner = crate::store::cow_percent_decode(&repo_seg[..slash]);
    let repo_name = crate::store::cow_percent_decode(&repo_seg[slash + 1..]);
    let sub_path = &pathname[git_idx + 4..];

    if method == "GET" && sub_path == "/info/refs" {
        let service = query_get(query, "service").unwrap_or("");
        if service == "git-upload-pack" {
            let is_v2 = git_protocol_header
                .map(|h| contains_ignore_ascii_case(h, "version=2"))
                .unwrap_or(false);
            let repo_id = {
                let g = store.inner.read().unwrap();
                let Some(id) = g.find_repo_id(&owner, &repo_name) else {
                    write_json_err_into(write_buf, 404, "Not Found");
                    return Some(GitResponse::Written);
                };
                if is_v2 {
                    return Some(GitResponse::Static(upload_v2_adv_http()));
                }
                if let Some(cached) = g.repos.get(&id).and_then(|r| r.upload_v0_http_cache.clone()) {
                    return Some(GitResponse::Cached(cached));
                }
                id
            };
            let mut g = store.inner.write().unwrap();
            if let Some(r) = g.repos.get_mut(&repo_id) {
                if let Some(c) = &r.upload_v0_http_cache {
                    return Some(GitResponse::Cached(c.clone()));
                }
                let built = build_upload_v0_http(r);
                r.upload_v0_http_cache = Some(built.clone());
                return Some(GitResponse::Cached(built));
            }
            write_json_err_into(write_buf, 404, "Not Found");
            return Some(GitResponse::Written);
        }
        if service == "git-receive-pack" {
            let repo_id = {
                let g = store.inner.read().unwrap();
                let Some(id) = g.find_repo_id(&owner, &repo_name) else {
                    write_json_err_into(write_buf, 404, "Not Found");
                    return Some(GitResponse::Written);
                };
                if let Some(cached) = g.repos.get(&id).and_then(|r| r.receive_v0_http_cache.clone()) {
                    return Some(GitResponse::Cached(cached));
                }
                id
            };
            let mut g = store.inner.write().unwrap();
            if let Some(r) = g.repos.get_mut(&repo_id) {
                if let Some(c) = &r.receive_v0_http_cache {
                    return Some(GitResponse::Cached(c.clone()));
                }
                let built = build_receive_v0_http(r);
                r.receive_v0_http_cache = Some(built.clone());
                return Some(GitResponse::Cached(built));
            }
            write_json_err_into(write_buf, 404, "Not Found");
            return Some(GitResponse::Written);
        }
        let exists = store.inner.read().unwrap().find_repo_id(&owner, &repo_name).is_some();
        if !exists {
            write_json_err_into(write_buf, 404, "Not Found");
        } else {
            write_json_err_into(write_buf, 400, "Unsupported git service");
        }
        return Some(GitResponse::Written);
    }

    if method == "POST" && sub_path == "/git-upload-pack" {
        let repo_id = {
            let g = store.inner.read().unwrap();
            let Some(id) = g.find_repo_id(&owner, &repo_name) else {
                write_json_err_into(write_buf, 404, "Not Found");
                return Some(GitResponse::Written);
            };
            if let Some(cached) = g
                .repos
                .get(&id)
                .and_then(|r| r.upload_pack_http_cache.get(body).cloned())
            {
                return Some(GitResponse::Cached(cached));
            }
            id
        };

        let (lines, _rest) = match parse_pkt_stream(body) {
            Ok(p) => p,
            Err(err) => {
                write_json_err_into(write_buf, 400, &err);
                return Some(GitResponse::Written);
            }
        };

        let mut cmd_kind = 0u8; // 0 = v0 fetch, 1 = ls-refs, 2 = fetch v2
        for &item in &lines {
            if let PktItem::Line(raw) = item {
                let l = raw.strip_suffix(b"\n").unwrap_or(raw);
                if l == b"command=ls-refs" {
                    cmd_kind = 1;
                    break;
                } else if l == b"command=fetch" {
                    cmd_kind = 2;
                    break;
                }
            }
        }

        let built_arc = {
            let g = store.inner.read().unwrap();
            let Some(repo) = g.repos.get(&repo_id) else {
                write_json_err_into(write_buf, 404, "Not Found");
                return Some(GitResponse::Written);
            };
            let bytes = match cmd_kind {
                1 => handle_ls_refs(repo, &lines),
                2 => handle_fetch_v2(repo, &lines),
                _ => handle_fetch_v0(repo, &lines),
            };
            Arc::new(bytes)
        };

        {
            let mut g = store.inner.write().unwrap();
            if let Some(repo) = g.repos.get_mut(&repo_id) {
                if repo.upload_pack_http_cache.len() < 64 && !repo.upload_pack_http_cache.contains_key(body) {
                    repo.upload_pack_http_cache.insert(body.to_vec(), built_arc.clone());
                }
            }
        }
        return Some(GitResponse::Cached(built_arc));
    }

    if method == "POST" && sub_path == "/git-receive-pack" {
        let (commands, use_sideband, pack_bytes) = match parse_receive_pack_request(body) {
            Ok(p) => p,
            Err(err) => {
                write_json_err_into(write_buf, 400, &err);
                return Some(GitResponse::Written);
            }
        };

        // Decode & SHA-1 verify incoming pack outside write lock first.
        let decoded_res: Result<Vec<DecodedObject>, String> = if pack_bytes.is_empty() {
            Ok(Vec::new())
        } else {
            match decoder.decode_pack(pack_bytes, |_| None) {
                Ok(objs) => Ok(objs),
                Err(err) if err.starts_with("Missing REF_DELTA base ") => {
                    let g = store.inner.read().unwrap();
                    match g
                        .find_repo_id(&owner, &repo_name)
                        .and_then(|id| g.repos.get(&id))
                    {
                        Some(repo) => decoder.decode_pack(pack_bytes, |oid| {
                            repo.objects.get(oid).map(|o| (o.kind, o.data.clone()))
                        }),
                        None => Err("Not Found".to_string()),
                    }
                }
                Err(err) => Err(err),
            }
        };

        match decoded_res {
            Err(unpack_err) => {
                let exists = store.inner.read().unwrap().find_repo_id(&owner, &repo_name).is_some();
                if !exists {
                    write_json_err_into(write_buf, 404, "Not Found");
                    return Some(GitResponse::Written);
                }
                let mut report_len = 4 + 14 + unpack_err.len() + 4;
                for cmd in &commands {
                    report_len += 4 + 3 + cmd.ref_name.len() + 15;
                }
                if report_len <= MAX_SIDEBAND_CHUNK {
                    let body_len = if use_sideband { 5 + report_len + 4 } else { report_len };
                    write_git_http_header(write_buf, b"application/x-git-receive-pack-result", body_len);
                    if use_sideband {
                        push_hex4(write_buf, 5 + report_len);
                        write_buf.push(0x01);
                    }
                    push_hex4(write_buf, 4 + 14 + unpack_err.len());
                    write_buf.extend_from_slice(b"unpack error ");
                    write_buf.extend_from_slice(unpack_err.as_bytes());
                    write_buf.push(b'\n');
                    for cmd in &commands {
                        push_hex4(write_buf, 4 + 3 + cmd.ref_name.len() + 15);
                        write_buf.extend_from_slice(b"ng ");
                        write_buf.extend_from_slice(cmd.ref_name.as_bytes());
                        write_buf.extend_from_slice(b" unpack failed\n");
                    }
                    write_buf.extend_from_slice(PKT_FLUSH);
                    if use_sideband {
                        write_buf.extend_from_slice(PKT_FLUSH);
                    }
                } else {
                    let mut report = Vec::with_capacity(report_len);
                    push_hex4(&mut report, 4 + 14 + unpack_err.len());
                    report.extend_from_slice(b"unpack error ");
                    report.extend_from_slice(unpack_err.as_bytes());
                    report.push(b'\n');
                    for cmd in &commands {
                        push_hex4(&mut report, 4 + 3 + cmd.ref_name.len() + 15);
                        report.extend_from_slice(b"ng ");
                        report.extend_from_slice(cmd.ref_name.as_bytes());
                        report.extend_from_slice(b" unpack failed\n");
                    }
                    report.extend_from_slice(PKT_FLUSH);
                    let mut sb = Vec::with_capacity(report.len() + 32);
                    if use_sideband {
                        wrap_sideband_64k(&mut sb, &report);
                        sb.extend_from_slice(PKT_FLUSH);
                    } else {
                        sb = report;
                    }
                    write_git_http_header(write_buf, b"application/x-git-receive-pack-result", sb.len());
                    write_buf.extend_from_slice(&sb);
                }
                return Some(GitResponse::Written);
            }
            Ok(objs) => {
                let (outcomes, updated_receive_adv) = {
                    let mut g = store.inner.write().unwrap();
                    let Some(repo_id) = g.find_repo_id(&owner, &repo_name) else {
                        write_json_err_into(write_buf, 404, "Not Found");
                        return Some(GitResponse::Written);
                    };
                    if let Some(repo) = g.repos.get_mut(&repo_id) {
                        repo.put_decoded(objs);
                    }
                    let res = g.apply_push_commands_ref(repo_id, &commands);
                    let adv_upd = if res.iter().any(|o| o.0) {
                        let new_epoch = store.bump_git_epoch_val();
                        let repo = g.repos.get_mut(&repo_id).unwrap();
                        let adv = build_receive_v0_http(repo);
                        repo.receive_v0_http_cache = Some(adv.clone());
                        Some((adv, new_epoch))
                    } else {
                        None
                    };
                    (res, adv_upd)
                };

                let mut report_len = 14 + 4; // "000eunpack ok\n" + "0000"
                for (cmd, &(ok, reason)) in commands.iter().zip(outcomes.iter()) {
                    if ok {
                        report_len += 4 + 3 + cmd.ref_name.len() + 1;
                    } else {
                        let r = if reason.is_empty() { "rejected" } else { reason };
                        report_len += 4 + 3 + cmd.ref_name.len() + 1 + r.len() + 1;
                    }
                }
                if report_len <= MAX_SIDEBAND_CHUNK {
                    let body_len = if use_sideband { 5 + report_len + 4 } else { report_len };
                    write_git_http_header(write_buf, b"application/x-git-receive-pack-result", body_len);
                    if use_sideband {
                        push_hex4(write_buf, 5 + report_len);
                        write_buf.push(0x01);
                    }
                    write_buf.extend_from_slice(b"000eunpack ok\n");
                    for (cmd, &(ok, reason)) in commands.iter().zip(outcomes.iter()) {
                        if ok {
                            push_hex4(write_buf, 4 + 3 + cmd.ref_name.len() + 1);
                            write_buf.extend_from_slice(b"ok ");
                            write_buf.extend_from_slice(cmd.ref_name.as_bytes());
                            write_buf.push(b'\n');
                        } else {
                            let r = if reason.is_empty() { "rejected" } else { reason };
                            push_hex4(write_buf, 4 + 3 + cmd.ref_name.len() + 1 + r.len() + 1);
                            write_buf.extend_from_slice(b"ng ");
                            write_buf.extend_from_slice(cmd.ref_name.as_bytes());
                            write_buf.push(b' ');
                            write_buf.extend_from_slice(r.as_bytes());
                            write_buf.push(b'\n');
                        }
                    }
                    write_buf.extend_from_slice(PKT_FLUSH);
                    if use_sideband {
                        write_buf.extend_from_slice(PKT_FLUSH);
                    }
                } else {
                    let mut report = Vec::with_capacity(report_len);
                    report.extend_from_slice(b"000eunpack ok\n");
                    for (cmd, &(ok, reason)) in commands.iter().zip(outcomes.iter()) {
                        if ok {
                            push_hex4(&mut report, 4 + 3 + cmd.ref_name.len() + 1);
                            report.extend_from_slice(b"ok ");
                            report.extend_from_slice(cmd.ref_name.as_bytes());
                            report.push(b'\n');
                        } else {
                            let r = if reason.is_empty() { "rejected" } else { reason };
                            push_hex4(&mut report, 4 + 3 + cmd.ref_name.len() + 1 + r.len() + 1);
                            report.extend_from_slice(b"ng ");
                            report.extend_from_slice(cmd.ref_name.as_bytes());
                            report.push(b' ');
                            report.extend_from_slice(r.as_bytes());
                            report.push(b'\n');
                        }
                    }
                    report.extend_from_slice(PKT_FLUSH);
                    let mut sb = Vec::with_capacity(report.len() + 32);
                    if use_sideband {
                        wrap_sideband_64k(&mut sb, &report);
                        sb.extend_from_slice(PKT_FLUSH);
                    } else {
                        sb = report;
                    }
                    write_git_http_header(write_buf, b"application/x-git-receive-pack-result", sb.len());
                    write_buf.extend_from_slice(&sb);
                }
                return Some(GitResponse::PushWritten { updated_receive_adv });
            }
        }
    }

    write_json_err_into(write_buf, 404, "Not Found");
    Some(GitResponse::Written)
}
