use std::borrow::Cow;
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};

use rustc_hash::{FxHashMap, FxHashSet};

use crate::pack::{deflate_best, DecodedObject};
use crate::sha1::{
    hash_git_object, hex_to_oid, oid_to_string, write_oid_hex, ObjKind, ZERO_OID,
};

const EPOCH_BASE_SEC: i64 = 1_763_100_000;

pub const VIEWER_ID: u64 = 1000;
pub const VIEWER_NODE_ID: &str = "U_adaiversen";
pub const VIEWER_LOGIN: &str = "adaiversen";
pub const VIEWER_NAME: &str = "Ada Iversen";
pub const VIEWER_EMAIL: &str = "adaiversen@make.fun";

#[inline]
fn push_2d(dst: &mut [u8], val: i64) {
    dst[0] = b'0' + ((val / 10) as u8);
    dst[1] = b'0' + ((val % 10) as u8);
}

pub fn format_iso_utc(unix_secs: i64) -> String {
    let days = unix_secs.div_euclid(86_400);
    let rem = unix_secs.rem_euclid(86_400);
    let hour = rem / 3600;
    let minute = (rem % 3600) / 60;
    let second = rem % 60;

    // Howard Hinnant's civil_from_days algorithm (days since 1970-01-01).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };

    let mut buf = [0u8; 24];
    let yr = year.clamp(0, 9999);
    buf[0] = b'0' + ((yr / 1000) as u8);
    buf[1] = b'0' + (((yr / 100) % 10) as u8);
    buf[2] = b'0' + (((yr / 10) % 10) as u8);
    buf[3] = b'0' + ((yr % 10) as u8);
    buf[4] = b'-';
    push_2d(&mut buf[5..7], m);
    buf[7] = b'-';
    push_2d(&mut buf[8..10], d);
    buf[10] = b'T';
    push_2d(&mut buf[11..13], hour);
    buf[13] = b':';
    push_2d(&mut buf[14..16], minute);
    buf[16] = b':';
    push_2d(&mut buf[17..19], second);
    buf[19..24].copy_from_slice(b".000Z");
    unsafe { String::from_utf8_unchecked(buf.to_vec()) }
}

pub fn json_escape_into(out: &mut Vec<u8>, s: &str) {
    out.push(b'"');
    let bytes = s.as_bytes();
    let mut last = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        let esc: Option<&[u8]> = match b {
            b'"' => Some(b"\\\""),
            b'\\' => Some(b"\\\\"),
            b'\x08' => Some(b"\\b"),
            b'\x0c' => Some(b"\\f"),
            b'\n' => Some(b"\\n"),
            b'\r' => Some(b"\\r"),
            b'\t' => Some(b"\\t"),
            0..=0x1f => None,
            _ => continue,
        };
        if i > last {
            out.extend_from_slice(&bytes[last..i]);
        }
        if let Some(seq) = esc {
            out.extend_from_slice(seq);
        } else {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            out.extend_from_slice(&[b'\\', b'u', b'0', b'0', HEX[(b >> 4) as usize], HEX[(b & 0xf) as usize]]);
        }
        last = i + 1;
    }
    if last < bytes.len() {
        out.extend_from_slice(&bytes[last..]);
    }
    out.push(b'"');
}

pub fn build_http_response(status_line: &[u8], content_type: &[u8], extra_headers: &[u8], body: &[u8]) -> Vec<u8> {
    let mut len_buf = itoa::Buffer::new();
    let len_str = len_buf.format(body.len());
    let mut buf = Vec::with_capacity(
        status_line.len() + content_type.len() + extra_headers.len() + body.len() + 96,
    );
    buf.extend_from_slice(status_line);
    buf.extend_from_slice(b"\r\nContent-Type: ");
    buf.extend_from_slice(content_type);
    buf.extend_from_slice(b"\r\nContent-Length: ");
    buf.extend_from_slice(len_str.as_bytes());
    buf.extend_from_slice(b"\r\nX-GitHub-Request-Id: 1\r\n");
    if !extra_headers.is_empty() {
        buf.extend_from_slice(extra_headers);
    }
    buf.extend_from_slice(b"\r\n");
    buf.extend_from_slice(body);
    buf
}

pub fn build_http_200_json(body: &[u8]) -> Arc<Vec<u8>> {
    Arc::new(build_http_response(
        b"HTTP/1.1 200 OK",
        b"application/json",
        b"",
        body,
    ))
}

const B64_STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn base64_encode(input: &[u8]) -> String {
    let mut out = Vec::with_capacity((input.len() + 2) / 3 * 4);
    let mut i = 0usize;
    while i + 3 <= input.len() {
        let v = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | (input[i + 2] as u32);
        out.push(B64_STD[((v >> 18) & 0x3f) as usize]);
        out.push(B64_STD[((v >> 12) & 0x3f) as usize]);
        out.push(B64_STD[((v >> 6) & 0x3f) as usize]);
        out.push(B64_STD[(v & 0x3f) as usize]);
        i += 3;
    }
    let rem = input.len() - i;
    if rem == 1 {
        let v = (input[i] as u32) << 16;
        out.push(B64_STD[((v >> 18) & 0x3f) as usize]);
        out.push(B64_STD[((v >> 12) & 0x3f) as usize]);
        out.push(b'=');
        out.push(b'=');
    } else if rem == 2 {
        let v = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8);
        out.push(B64_STD[((v >> 18) & 0x3f) as usize]);
        out.push(B64_STD[((v >> 12) & 0x3f) as usize]);
        out.push(B64_STD[((v >> 6) & 0x3f) as usize]);
        out.push(b'=');
    }
    unsafe { String::from_utf8_unchecked(out) }
}

pub fn base64url_encode(input: &[u8]) -> String {
    let mut out = Vec::with_capacity((input.len() + 2) / 3 * 4);
    let mut i = 0usize;
    while i + 3 <= input.len() {
        let v = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | (input[i + 2] as u32);
        out.push(B64_URL[((v >> 18) & 0x3f) as usize]);
        out.push(B64_URL[((v >> 12) & 0x3f) as usize]);
        out.push(B64_URL[((v >> 6) & 0x3f) as usize]);
        out.push(B64_URL[(v & 0x3f) as usize]);
        i += 3;
    }
    let rem = input.len() - i;
    if rem == 1 {
        let v = (input[i] as u32) << 16;
        out.push(B64_URL[((v >> 18) & 0x3f) as usize]);
        out.push(B64_URL[((v >> 12) & 0x3f) as usize]);
    } else if rem == 2 {
        let v = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8);
        out.push(B64_URL[((v >> 18) & 0x3f) as usize]);
        out.push(B64_URL[((v >> 12) & 0x3f) as usize]);
        out.push(B64_URL[((v >> 6) & 0x3f) as usize]);
    }
    unsafe { String::from_utf8_unchecked(out) }
}

pub fn base64_decode_lenient(input: &[u8]) -> Option<Vec<u8>> {
    let mut vals = Vec::with_capacity(input.len());
    for &b in input {
        if b.is_ascii_whitespace() || b == b'=' {
            continue;
        }
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        };
        vals.push(v);
    }
    let mut out = Vec::with_capacity(vals.len() * 3 / 4);
    let mut i = 0usize;
    while i + 4 <= vals.len() {
        let n = ((vals[i] as u32) << 18)
            | ((vals[i + 1] as u32) << 12)
            | ((vals[i + 2] as u32) << 6)
            | (vals[i + 3] as u32);
        out.push((n >> 16) as u8);
        out.push((n >> 8) as u8);
        out.push(n as u8);
        i += 4;
    }
    let rem = vals.len() - i;
    if rem == 2 {
        let n = ((vals[i] as u32) << 18) | ((vals[i + 1] as u32) << 12);
        out.push((n >> 16) as u8);
    } else if rem == 3 {
        let n = ((vals[i] as u32) << 18) | ((vals[i + 1] as u32) << 12) | ((vals[i + 2] as u32) << 6);
        out.push((n >> 16) as u8);
        out.push((n >> 8) as u8);
    } else if rem == 1 {
        return None;
    }
    Some(out)
}

pub fn cow_percent_decode(raw: &str) -> Cow<'_, str> {
    if !raw.as_bytes().contains(&b'%') {
        Cow::Borrowed(raw)
    } else {
        Cow::Owned(percent_decode(raw))
    }
}

pub fn percent_decode(raw: &str) -> String {
    if !raw.as_bytes().contains(&b'%') {
        return raw.to_string();
    }
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

pub struct GitObject {
    #[allow(dead_code)]
    pub oid: [u8; 20],
    pub kind: ObjKind,
    pub data: Vec<u8>,
    pub tree_oid: Option<[u8; 20]>,
    pub parent0: Option<[u8; 20]>,
    pub extra_parents: Vec<[u8; 20]>,
    pub tag_target: Option<[u8; 20]>,
    pub compressed: OnceLock<Vec<u8>>,
}

impl GitObject {
    pub fn compressed_bytes(&self) -> &[u8] {
        self.compressed.get_or_init(|| deflate_best(&self.data))
    }

    #[inline]
    pub fn has_parents(&self) -> bool {
        self.parent0.is_some()
    }

    #[inline]
    pub fn has_parent(&self, oid: &[u8; 20]) -> bool {
        self.parent0.as_ref() == Some(oid) || self.extra_parents.contains(oid)
    }

    #[inline]
    pub fn for_each_parent(&self, mut f: impl FnMut([u8; 20])) {
        if let Some(p0) = self.parent0 {
            f(p0);
        }
        for &p in &self.extra_parents {
            f(p);
        }
    }
}

pub fn make_git_object(oid: [u8; 20], kind: ObjKind, data: Vec<u8>) -> GitObject {
    let mut tree_oid = None;
    let mut parent0 = None;
    let mut extra_parents = Vec::new();
    let mut tag_target = None;

    match kind {
        ObjKind::Commit => {
            let head_end = find_double_nl(&data).unwrap_or(data.len());
            for line in data[..head_end].split(|&b| b == b'\n') {
                if let Some(rest) = line.strip_prefix(b"tree ") {
                    if let Some(t) = hex_to_oid(rest.trim_ascii_end()) {
                        tree_oid = Some(t);
                    }
                } else if let Some(rest) = line.strip_prefix(b"parent ") {
                    if let Some(p) = hex_to_oid(rest.trim_ascii_end()) {
                        if parent0.is_none() {
                            parent0 = Some(p);
                        } else {
                            extra_parents.push(p);
                        }
                    }
                }
            }
        }
        ObjKind::Tag => {
            let head_end = find_double_nl(&data).unwrap_or(data.len());
            for line in data[..head_end].split(|&b| b == b'\n') {
                if let Some(rest) = line.strip_prefix(b"object ") {
                    if let Some(t) = hex_to_oid(rest.trim_ascii_end()) {
                        tag_target = Some(t);
                    }
                }
            }
        }
        ObjKind::Tree | ObjKind::Blob => {}
    }

    GitObject {
        oid,
        kind,
        data,
        tree_oid,
        parent0,
        extra_parents,
        tag_target,
        compressed: OnceLock::new(),
    }
}

fn find_double_nl(data: &[u8]) -> Option<usize> {
    data.windows(2).position(|w| w == b"\n\n")
}

pub fn parse_commit_message_and_author(data: &[u8]) -> (String, String, Vec<[u8; 20]>) {
    let head_end = find_double_nl(data);
    let (head, msg) = match head_end {
        Some(pos) => (&data[..pos], &data[pos + 2..]),
        None => (data, &[][..]),
    };
    let mut author = String::new();
    let mut parents = Vec::new();
    for line in head.split(|&b| b == b'\n') {
        if let Some(rest) = line.strip_prefix(b"author ") {
            author = String::from_utf8_lossy(rest.trim_ascii_end()).into_owned();
        } else if let Some(rest) = line.strip_prefix(b"parent ") {
            if let Some(p) = hex_to_oid(rest.trim_ascii_end()) {
                parents.push(p);
            }
        }
    }
    let mut msg_str = String::from_utf8_lossy(msg).into_owned();
    if msg_str.ends_with('\n') {
        msg_str.pop();
    }
    (msg_str, author, parents)
}

#[derive(Clone)]
pub struct TreeItem {
    pub mode: String,
    pub name: String,
    pub oid: [u8; 20],
}

pub fn parse_tree_entries(data: &[u8]) -> Result<Vec<TreeItem>, String> {
    let mut items = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let sp = memchr::memchr(b' ', &data[pos..])
            .map(|r| pos + r)
            .ok_or_else(|| "Malformed tree entry: missing mode separator".to_string())?;
        let nul = memchr::memchr(0, &data[sp + 1..])
            .map(|r| sp + 1 + r)
            .ok_or_else(|| "Malformed tree entry: missing nul".to_string())?;
        if nul + 21 > data.len() {
            return Err("Malformed tree entry: truncated OID".to_string());
        }
        let mode = String::from_utf8_lossy(&data[pos..sp]).into_owned();
        let name = String::from_utf8_lossy(&data[sp + 1..nul]).into_owned();
        let mut oid = [0u8; 20];
        oid.copy_from_slice(&data[nul + 1..nul + 21]);
        items.push(TreeItem { mode, name, oid });
        pos = nul + 21;
    }
    Ok(items)
}

pub fn encode_tree_bytes(mut items: Vec<TreeItem>) -> Vec<u8> {
    items.sort_by(|a, b| {
        let ka = if a.mode == "40000" || a.mode == "040000" {
            format!("{}/", a.name)
        } else {
            a.name.clone()
        };
        let kb = if b.mode == "40000" || b.mode == "040000" {
            format!("{}/", b.name)
        } else {
            b.name.clone()
        };
        ka.as_bytes().cmp(kb.as_bytes())
    });
    let mut out = Vec::with_capacity(items.len() * 36);
    for item in items {
        let norm_mode = if item.mode == "040000" { "40000" } else { &item.mode };
        out.extend_from_slice(norm_mode.as_bytes());
        out.push(b' ');
        out.extend_from_slice(item.name.as_bytes());
        out.push(0);
        out.extend_from_slice(&item.oid);
    }
    out
}

pub fn encode_commit_bytes(
    tree_oid: &[u8; 20],
    parents: &[[u8; 20]],
    author: &str,
    timestamp_sec: i64,
    message: &str,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(256 + message.len());
    out.extend_from_slice(b"tree ");
    write_oid_hex(&mut out, tree_oid);
    out.push(b'\n');
    for p in parents {
        out.extend_from_slice(b"parent ");
        write_oid_hex(&mut out, p);
        out.push(b'\n');
    }
    let mut ts_buf = itoa::Buffer::new();
    let ts_str = ts_buf.format(timestamp_sec);
    out.extend_from_slice(b"author ");
    out.extend_from_slice(author.as_bytes());
    out.push(b' ');
    out.extend_from_slice(ts_str.as_bytes());
    out.extend_from_slice(b" +0000\ncommitter ");
    out.extend_from_slice(author.as_bytes());
    out.push(b' ');
    out.extend_from_slice(ts_str.as_bytes());
    out.extend_from_slice(b" +0000\n\n");
    out.extend_from_slice(message.as_bytes());
    if !message.ends_with('\n') {
        out.push(b'\n');
    }
    out
}

#[derive(Clone)]
pub struct FlatFileEntry {
    pub mode: String,
    pub oid: [u8; 20],
    pub data: Vec<u8>,
}

#[derive(Clone)]
pub struct Label {
    pub id: u64,
    pub node_id: String,
    pub name: String,
    pub color: String,
    pub description: String,
}

#[derive(Clone)]
pub struct Comment {
    pub id: u64,
    pub node_id: String,
    pub body: String,
    pub user_login: &'static str,
    pub user_id: u64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone)]
pub struct Issue {
    pub id: u64,
    pub node_id: String,
    pub number: u64,
    pub title: String,
    pub body: String,
    pub is_open: bool,
    pub labels: Vec<Label>,
    pub user_login: &'static str,
    pub user_id: u64,
    pub created_seq: u64,
    pub created_at: String,
    pub updated_at: String,
    pub closed_at: Option<String>,
    pub comments: Vec<Comment>,
    pub json_cache: Option<Arc<Vec<u8>>>,
    pub http_200_cache: Option<Arc<Vec<u8>>>,
}

impl Issue {
    pub fn state_str(&self) -> &'static str {
        if self.is_open { "open" } else { "closed" }
    }

    pub fn invalidate_cache(&mut self) {
        self.json_cache = None;
        self.http_200_cache = None;
    }

    pub fn ensure_json_and_http(&mut self) -> (Arc<Vec<u8>>, Arc<Vec<u8>>) {
        if let (Some(j), Some(h)) = (&self.json_cache, &self.http_200_cache) {
            return (j.clone(), h.clone());
        }
        let mut buf = Vec::with_capacity(256 + self.title.len() + self.body.len());
        write_issue_json_into(&mut buf, self);
        let j = Arc::new(buf);
        let h = build_http_200_json(&j);
        self.json_cache = Some(j.clone());
        self.http_200_cache = Some(h.clone());
        (j, h)
    }
}

pub fn write_issue_json_into(out: &mut Vec<u8>, issue: &Issue) {
    let mut ibuf = itoa::Buffer::new();
    out.extend_from_slice(b"{\"id\":");
    out.extend_from_slice(ibuf.format(issue.id).as_bytes());
    out.extend_from_slice(b",\"node_id\":");
    json_escape_into(out, &issue.node_id);
    out.extend_from_slice(b",\"number\":");
    out.extend_from_slice(ibuf.format(issue.number).as_bytes());
    out.extend_from_slice(b",\"title\":");
    json_escape_into(out, &issue.title);
    out.extend_from_slice(b",\"body\":");
    json_escape_into(out, &issue.body);
    out.extend_from_slice(b",\"state\":\"");
    out.extend_from_slice(issue.state_str().as_bytes());
    out.extend_from_slice(b"\",\"labels\":[");
    for (idx, lbl) in issue.labels.iter().enumerate() {
        if idx > 0 {
            out.push(b',');
        }
        out.extend_from_slice(b"{\"id\":");
        out.extend_from_slice(ibuf.format(lbl.id).as_bytes());
        out.extend_from_slice(b",\"node_id\":");
        json_escape_into(out, &lbl.node_id);
        out.extend_from_slice(b",\"name\":");
        json_escape_into(out, &lbl.name);
        out.extend_from_slice(b",\"color\":");
        json_escape_into(out, &lbl.color);
        out.extend_from_slice(b",\"description\":");
        json_escape_into(out, &lbl.description);
        out.push(b'}');
    }
    out.extend_from_slice(b"],\"user\":{\"login\":");
    json_escape_into(out, &issue.user_login);
    out.extend_from_slice(b",\"id\":");
    out.extend_from_slice(ibuf.format(issue.user_id).as_bytes());
    out.extend_from_slice(b",\"type\":\"User\"},\"comments\":");
    out.extend_from_slice(ibuf.format(issue.comments.len()).as_bytes());
    out.extend_from_slice(b",\"created_at\":");
    json_escape_into(out, &issue.created_at);
    out.extend_from_slice(b",\"updated_at\":");
    json_escape_into(out, &issue.updated_at);
    out.extend_from_slice(b",\"closed_at\":");
    match &issue.closed_at {
        Some(ts) => json_escape_into(out, ts),
        None => out.extend_from_slice(b"null"),
    }
    out.push(b'}');
}

#[derive(Clone)]
pub struct Pull {
    pub id: u64,
    pub node_id: String,
    pub number: u64,
    pub title: String,
    pub body: String,
    pub is_open: bool,
    pub head_ref: String,
    pub base_ref: String,
    pub head_sha: [u8; 20],
    pub base_sha: [u8; 20],
    pub merged: bool,
    pub merged_at: Option<String>,
    pub merge_commit_sha: Option<[u8; 20]>,
    pub user_login: &'static str,
    pub user_id: u64,
    pub created_seq: u64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone)]
pub struct PullFileChange {
    pub filename: String,
    pub status: &'static str,
    pub additions: usize,
    pub deletions: usize,
    pub changes: usize,
}

pub struct Repo {
    pub id: u64,
    pub node_id: String,
    pub owner: String,
    pub name: String,
    pub description: String,
    pub private: bool,
    pub default_branch: String,
    pub created_at: String,
    pub updated_at: String,
    pub objects: FxHashMap<[u8; 20], GitObject>,
    pub refs: BTreeMap<String, [u8; 20]>,
    pub labels: FxHashMap<String, Label>,
    pub label_order: Vec<String>,
    pub issues: FxHashMap<u64, Issue>,
    pub issue_order: Vec<u64>,
    pub pulls: FxHashMap<u64, Pull>,
    pub pull_order: Vec<u64>,
    pub next_number: u64,
    pub upload_v0_http_cache: Option<Arc<Vec<u8>>>,
    pub receive_v0_http_cache: Option<Arc<Vec<u8>>>,
    pub upload_pack_http_cache: FxHashMap<Vec<u8>, Arc<Vec<u8>>>,
}

impl Repo {
    pub fn invalidate_git_caches(&mut self) {
        self.upload_v0_http_cache = None;
        self.receive_v0_http_cache = None;
        if !self.upload_pack_http_cache.is_empty() {
            self.upload_pack_http_cache.clear();
        }
    }

    pub fn head_ref_name(&self) -> String {
        format!("refs/heads/{}", self.default_branch)
    }

    pub fn put_object_bytes(&mut self, kind: ObjKind, data: Vec<u8>) -> [u8; 20] {
        let oid = hash_git_object(kind, &data);
        self.objects
            .entry(oid)
            .or_insert_with(|| make_git_object(oid, kind, data));
        oid
    }

    pub fn put_decoded(&mut self, decoded: Vec<DecodedObject>) {
        for obj in decoded {
            let oid = obj.oid;
            self.objects
                .entry(oid)
                .or_insert_with(|| make_git_object(oid, obj.kind, obj.data));
        }
    }

    pub fn peel_tag(&self, oid: &[u8; 20]) -> Option<[u8; 20]> {
        let mut cur = *oid;
        for hop in 0..8 {
            let obj = self.objects.get(&cur)?;
            if obj.kind != ObjKind::Tag {
                return if hop == 0 { None } else { Some(cur) };
            }
            cur = obj.tag_target?;
        }
        Some(cur)
    }

    pub fn is_ancestor(&self, ancestor_oid: &[u8; 20], descendant_oid: &[u8; 20]) -> bool {
        if ancestor_oid == descendant_oid {
            return true;
        }
        let Some(tip) = self.objects.get(descendant_oid) else {
            return false;
        };
        if tip.kind != ObjKind::Commit {
            return false;
        }
        if tip.has_parent(ancestor_oid) {
            return true;
        }
        let mut visited = FxHashSet::default();
        visited.insert(*descendant_oid);
        let mut queue = Vec::with_capacity(8);
        tip.for_each_parent(|p| queue.push(p));
        while let Some(cur) = queue.pop() {
            if &cur == ancestor_oid {
                return true;
            }
            if !visited.insert(cur) {
                continue;
            }
            if let Some(obj) = self.objects.get(&cur) {
                obj.for_each_parent(|p| {
                    if !visited.contains(&p) {
                        queue.push(p);
                    }
                });
            }
        }
        false
    }

    pub fn resolve_ref_oid(&self, ref_or_sha: Option<&str>) -> Option<[u8; 20]> {
        let target = match ref_or_sha {
            Some(s) if !s.is_empty() => s,
            _ => &self.default_branch,
        };
        if target.len() == 40 {
            if let Some(oid) = hex_to_oid(target.as_bytes()) {
                if self.objects.contains_key(&oid) {
                    return Some(oid);
                }
            }
        }
        if target.starts_with("refs/") {
            return self.refs.get(target).copied();
        }
        self.refs
            .get(&format!("refs/heads/{target}"))
            .or_else(|| self.refs.get(&format!("refs/tags/{target}")))
            .copied()
    }

    pub fn flatten_tree(&self, tree_or_commit: &[u8; 20]) -> BTreeMap<String, FlatFileEntry> {
        let mut out = BTreeMap::new();
        let Some(obj) = self.objects.get(tree_or_commit) else {
            return out;
        };
        let root_tree = if obj.kind == ObjKind::Commit {
            match obj.tree_oid {
                Some(t) => t,
                None => return out,
            }
        } else {
            *tree_or_commit
        };

        fn walk(
            repo: &Repo,
            tree_oid: &[u8; 20],
            prefix: &str,
            out: &mut BTreeMap<String, FlatFileEntry>,
        ) {
            let Some(tree_obj) = repo.objects.get(tree_oid) else {
                return;
            };
            if tree_obj.kind != ObjKind::Tree {
                return;
            }
            let Ok(entries) = parse_tree_entries(&tree_obj.data) else {
                return;
            };
            for entry in entries {
                let full = if prefix.is_empty() {
                    entry.name
                } else {
                    format!("{prefix}/{}", entry.name)
                };
                if entry.mode == "40000" || entry.mode == "040000" {
                    walk(repo, &entry.oid, &full, out);
                } else if let Some(blob) = repo.objects.get(&entry.oid) {
                    out.insert(
                        full,
                        FlatFileEntry {
                            mode: entry.mode,
                            oid: entry.oid,
                            data: blob.data.clone(),
                        },
                    );
                }
            }
        }

        walk(self, &root_tree, "", &mut out);
        out
    }

    pub fn write_tree_from_flat(&mut self, files: &BTreeMap<String, FlatFileEntry>) -> [u8; 20] {
        #[derive(Default)]
        struct DirNode {
            files: BTreeMap<String, (String, [u8; 20])>,
            dirs: BTreeMap<String, DirNode>,
        }

        let mut root = DirNode::default();
        for (path, entry) in files {
            let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
            if segs.is_empty() {
                continue;
            }
            let mut cur = &mut root;
            for &seg in &segs[..segs.len() - 1] {
                cur = cur.dirs.entry(seg.to_string()).or_default();
            }
            cur.files
                .insert(segs[segs.len() - 1].to_string(), (entry.mode.clone(), entry.oid));
        }

        fn build(repo: &mut Repo, node: DirNode) -> [u8; 20] {
            let mut items = Vec::with_capacity(node.files.len() + node.dirs.len());
            for (name, (mode, oid)) in node.files {
                items.push(TreeItem { mode, name, oid });
            }
            for (name, sub) in node.dirs {
                let oid = build(repo, sub);
                items.push(TreeItem {
                    mode: "40000".to_string(),
                    name,
                    oid,
                });
            }
            repo.put_object_bytes(ObjKind::Tree, encode_tree_bytes(items))
        }

        build(self, root)
    }

    pub fn find_merge_base(&self, commit_a: &[u8; 20], commit_b: &[u8; 20]) -> Option<[u8; 20]> {
        let mut ancestors_a = FxHashSet::default();
        let mut qa = vec![*commit_a];
        while let Some(c) = qa.pop() {
            if !ancestors_a.insert(c) {
                continue;
            }
            if let Some(obj) = self.objects.get(&c) {
                obj.for_each_parent(|p| qa.push(p));
            }
        }
        let mut visited_b = FxHashSet::default();
        let mut qb = VecDeque::new();
        qb.push_back(*commit_b);
        while let Some(c) = qb.pop_front() {
            if ancestors_a.contains(&c) {
                return Some(c);
            }
            if !visited_b.insert(c) {
                continue;
            }
            if let Some(obj) = self.objects.get(&c) {
                obj.for_each_parent(|p| qb.push_back(p));
            }
        }
        None
    }

    pub fn compute_changed_files(&self, base_oid: &[u8; 20], head_oid: &[u8; 20]) -> Vec<PullFileChange> {
        let merge_base = self.find_merge_base(base_oid, head_oid).unwrap_or(*base_oid);
        let base_files = self.flatten_tree(&merge_base);
        let head_files = self.flatten_tree(head_oid);

        let mut all_paths = BTreeMap::new();
        for p in base_files.keys() {
            all_paths.insert(p.as_str(), ());
        }
        for p in head_files.keys() {
            all_paths.insert(p.as_str(), ());
        }

        fn count_lines(buf: &[u8]) -> usize {
            if buf.is_empty() {
                return 0;
            }
            let n = buf.split(|&b| b == b'\n').count();
            if buf.ends_with(b"\n") {
                n.saturating_sub(1).max(1)
            } else {
                n
            }
        }

        let mut changes = Vec::new();
        for p in all_paths.keys() {
            let b = base_files.get(*p);
            let h = head_files.get(*p);
            match (b, h) {
                (None, Some(hf)) => {
                    let adds = count_lines(&hf.data).max(1);
                    changes.push(PullFileChange {
                        filename: (*p).to_string(),
                        status: "added",
                        additions: adds,
                        deletions: 0,
                        changes: adds,
                    });
                }
                (Some(bf), None) => {
                    let dels = count_lines(&bf.data).max(1);
                    changes.push(PullFileChange {
                        filename: (*p).to_string(),
                        status: "removed",
                        additions: 0,
                        deletions: dels,
                        changes: dels,
                    });
                }
                (Some(bf), Some(hf)) if bf.oid != hf.oid => {
                    let adds = hf.data.split(|&c| c == b'\n').count().max(1);
                    let dels = bf.data.split(|&c| c == b'\n').count().max(1);
                    changes.push(PullFileChange {
                        filename: (*p).to_string(),
                        status: "modified",
                        additions: adds,
                        deletions: dels,
                        changes: adds + dels,
                    });
                }
                _ => {}
            }
        }
        changes
    }

    pub fn compute_three_way_merge(
        &self,
        base_tip: &[u8; 20],
        head_tip: &[u8; 20],
    ) -> Option<BTreeMap<String, FlatFileEntry>> {
        let lca = self.find_merge_base(base_tip, head_tip);
        let lca_files = match lca {
            Some(oid) => self.flatten_tree(&oid),
            None => BTreeMap::new(),
        };
        let base_files = self.flatten_tree(base_tip);
        let head_files = self.flatten_tree(head_tip);

        let mut paths = FxHashSet::default();
        for p in lca_files.keys() {
            paths.insert(p.clone());
        }
        for p in base_files.keys() {
            paths.insert(p.clone());
        }
        for p in head_files.keys() {
            paths.insert(p.clone());
        }

        fn same_entry(x: Option<&FlatFileEntry>, y: Option<&FlatFileEntry>) -> bool {
            match (x, y) {
                (None, None) => true,
                (Some(a), Some(b)) => a.oid == b.oid && a.mode == b.mode,
                _ => false,
            }
        }

        let mut merged = BTreeMap::new();
        for p in paths {
            let a = lca_files.get(&p);
            let b = base_files.get(&p);
            let h = head_files.get(&p);
            if same_entry(b, h) {
                if let Some(entry) = b {
                    merged.insert(p, entry.clone());
                }
            } else if same_entry(a, b) {
                if let Some(entry) = h {
                    merged.insert(p, entry.clone());
                }
            } else if same_entry(a, h) {
                if let Some(entry) = b {
                    merged.insert(p, entry.clone());
                }
            } else {
                return None;
            }
        }
        Some(merged)
    }

    pub fn is_pull_mergeable(&self, pull: &Pull) -> &'static str {
        if pull.merged {
            return "MERGEABLE";
        }
        let base_tip = self
            .refs
            .get(&format!("refs/heads/{}", pull.base_ref))
            .copied()
            .unwrap_or(pull.base_sha);
        let head_tip = self
            .refs
            .get(&format!("refs/heads/{}", pull.head_ref))
            .copied()
            .unwrap_or(pull.head_sha);
        if self.compute_three_way_merge(&base_tip, &head_tip).is_some() {
            "MERGEABLE"
        } else {
            "CONFLICTING"
        }
    }
}

#[derive(Clone)]
pub enum NodeTarget {
    Repository(u64),
    Issue(u64, u64),
    PullRequest(u64, u64),
    IssueComment(u64, u64, usize),
}

pub enum ReadContentsResult {
    File {
        name: String,
        path: String,
        sha: String,
        size: usize,
        content_base64: String,
    },
    Dir(Vec<DirContentEntry>),
}

pub struct DirContentEntry {
    pub kind: &'static str,
    pub name: String,
    pub path: String,
    pub sha: String,
    pub size: usize,
}

pub struct PushCommandRef<'a> {
    pub old_oid: [u8; 20],
    pub new_oid: [u8; 20],
    pub ref_name: &'a str,
}

pub struct StoreInner {
    pub next_entity_id: u64,
    pub seq: u64,
    pub repos_by_owner: FxHashMap<String, FxHashMap<String, u64>>,
    pub repos: FxHashMap<u64, Repo>,
    pub viewer_repo_order: Vec<u64>,
    pub nodes_by_id: FxHashMap<String, NodeTarget>,
}

impl StoreInner {
    fn new() -> Self {
        let mut repos_by_owner = FxHashMap::default();
        repos_by_owner.insert(VIEWER_LOGIN.to_string(), FxHashMap::default());
        Self {
            next_entity_id: 10_000,
            seq: 1,
            repos_by_owner,
            repos: FxHashMap::default(),
            viewer_repo_order: Vec::new(),
            nodes_by_id: FxHashMap::default(),
        }
    }

    pub fn next_stamp(&mut self) -> (u64, String, i64) {
        let seq = self.seq;
        self.seq += 1;
        let epoch_sec = EPOCH_BASE_SEC + seq as i64;
        let iso = format_iso_utc(epoch_sec);
        (seq, iso, epoch_sec)
    }

    pub fn alloc_id(&mut self) -> u64 {
        let id = self.next_entity_id;
        self.next_entity_id += 1;
        id
    }

    pub fn find_repo_id(&self, owner: &str, name: &str) -> Option<u64> {
        if owner != VIEWER_LOGIN {
            return None;
        }
        self.repos_by_owner.get(owner)?.get(name).copied()
    }

    pub fn get_repo(&self, owner: &str, name: &str) -> Option<&Repo> {
        let id = self.find_repo_id(owner, name)?;
        self.repos.get(&id)
    }

    pub fn get_repo_mut(&mut self, owner: &str, name: &str) -> Option<&mut Repo> {
        let id = self.find_repo_id(owner, name)?;
        self.repos.get_mut(&id)
    }

    pub fn create_repo(
        &mut self,
        owner: &str,
        name: &str,
        description: &str,
        is_private: bool,
    ) -> Result<u64, (u16, String)> {
        if name.trim().is_empty() {
            return Err((422, "Repository name is required".to_string()));
        }
        let owner_map = self
            .repos_by_owner
            .entry(owner.to_string())
            .or_insert_with(FxHashMap::default);
        if owner_map.contains_key(name) {
            return Err((
                422,
                "Repository creation failed: name already exists on this account".to_string(),
            ));
        }
        let (_seq, iso, _) = self.next_stamp();
        let id = self.alloc_id();
        let node_id = format!("R_{id}");
        let repo = Repo {
            id,
            node_id: node_id.clone(),
            owner: owner.to_string(),
            name: name.to_string(),
            description: description.to_string(),
            private: is_private,
            default_branch: "main".to_string(),
            created_at: iso.clone(),
            updated_at: iso,
            objects: FxHashMap::with_capacity_and_hasher(64, Default::default()),
            refs: BTreeMap::new(),
            labels: FxHashMap::default(),
            label_order: Vec::new(),
            issues: FxHashMap::with_capacity_and_hasher(64, Default::default()),
            issue_order: Vec::new(),
            pulls: FxHashMap::default(),
            pull_order: Vec::new(),
            next_number: 1,
            upload_v0_http_cache: None,
            receive_v0_http_cache: None,
            upload_pack_http_cache: FxHashMap::default(),
        };
        self.repos.insert(id, repo);
        self.repos_by_owner
            .get_mut(owner)
            .unwrap()
            .insert(name.to_string(), id);
        if owner == VIEWER_LOGIN {
            self.viewer_repo_order.push(id);
        }
        self.nodes_by_id.insert(node_id, NodeTarget::Repository(id));
        Ok(id)
    }

    pub fn delete_repo(&mut self, owner: &str, name: &str) -> bool {
        let Some(owner_map) = self.repos_by_owner.get_mut(owner) else {
            return false;
        };
        let Some(id) = owner_map.remove(name) else {
            return false;
        };
        if let Some(repo) = self.repos.remove(&id) {
            self.nodes_by_id.remove(&repo.node_id);
            for issue in repo.issues.values() {
                self.nodes_by_id.remove(&issue.node_id);
                for c in &issue.comments {
                    self.nodes_by_id.remove(&c.node_id);
                }
            }
            for pull in repo.pulls.values() {
                self.nodes_by_id.remove(&pull.node_id);
            }
        }
        if owner == VIEWER_LOGIN {
            if let Some(pos) = self.viewer_repo_order.iter().position(|&rid| rid == id) {
                self.viewer_repo_order.remove(pos);
            }
        }
        true
    }

    pub fn create_label(
        &mut self,
        repo_id: u64,
        name: &str,
        color: &str,
        description: &str,
    ) -> Label {
        if let Some(existing) = self.repos.get(&repo_id).and_then(|r| r.labels.get(name)) {
            return existing.clone();
        }
        let id = self.alloc_id();
        let label = Label {
            id,
            node_id: format!("LA_{id}"),
            name: name.to_string(),
            color: color.to_string(),
            description: description.to_string(),
        };
        let repo = self.repos.get_mut(&repo_id).unwrap();
        repo.labels.insert(name.to_string(), label.clone());
        repo.label_order.push(name.to_string());
        label
    }

    pub fn create_issue(
        &mut self,
        repo_id: u64,
        title: &str,
        body: &str,
        label_names: Option<&[String]>,
    ) -> Result<u64, (u16, String)> {
        let mut resolved_labels = Vec::new();
        if let Some(names) = label_names {
            let repo = self
                .repos
                .get(&repo_id)
                .ok_or_else(|| (404u16, "Not Found".to_string()))?;
            resolved_labels.reserve(names.len());
            for name in names {
                match repo.labels.get(name) {
                    Some(lbl) => resolved_labels.push(lbl.clone()),
                    None => {
                        return Err((
                            422,
                            format!("Validation Failed: unknown label {name}"),
                        ))
                    }
                }
            }
        }
        let (seq, iso, _) = self.next_stamp();
        let id = self.alloc_id();
        let Some(repo) = self.repos.get_mut(&repo_id) else {
            return Err((404, "Not Found".to_string()));
        };
        let number = repo.next_number;
        repo.next_number += 1;
        let mut ibuf = itoa::Buffer::new();
        let mut node_id = String::with_capacity(12);
        node_id.push_str("I_");
        node_id.push_str(ibuf.format(id));
        let issue = Issue {
            id,
            node_id: node_id.clone(),
            number,
            title: title.to_string(),
            body: body.to_string(),
            is_open: true,
            labels: resolved_labels,
            user_login: VIEWER_LOGIN,
            user_id: VIEWER_ID,
            created_seq: seq,
            created_at: iso.clone(),
            updated_at: iso,
            closed_at: None,
            comments: Vec::new(),
            json_cache: None,
            http_200_cache: None,
        };
        repo.issues.insert(number, issue);
        repo.issue_order.push(number);
        self.nodes_by_id
            .insert(node_id, NodeTarget::Issue(repo_id, number));
        Ok(number)
    }

    pub fn update_issue(
        &mut self,
        repo_id: u64,
        number: u64,
        title: Option<&str>,
        body: Option<&str>,
        state: Option<bool>,
    ) -> bool {
        let (_seq, iso, _) = self.next_stamp();
        let Some(repo) = self.repos.get_mut(&repo_id) else {
            return false;
        };
        let Some(issue) = repo.issues.get_mut(&number) else {
            return false;
        };
        if let Some(t) = title {
            issue.title = t.to_string();
        }
        if let Some(b) = body {
            issue.body = b.to_string();
        }
        if let Some(is_open) = state {
            if is_open != issue.is_open {
                issue.is_open = is_open;
                issue.closed_at = if is_open { None } else { Some(iso.clone()) };
            }
        }
        issue.updated_at = iso;
        issue.invalidate_cache();
        true
    }

    pub fn add_comment(&mut self, repo_id: u64, issue_number: u64, body: &str) -> Option<Comment> {
        let (_seq, iso, _) = self.next_stamp();
        let id = self.alloc_id();
        let node_id = format!("IC_{id}");
        let comment = Comment {
            id,
            node_id: node_id.clone(),
            body: body.to_string(),
            user_login: VIEWER_LOGIN,
            user_id: VIEWER_ID,
            created_at: iso.clone(),
            updated_at: iso,
        };
        let repo = self.repos.get_mut(&repo_id)?;
        let issue = repo.issues.get_mut(&issue_number)?;
        let idx = issue.comments.len();
        issue.comments.push(comment.clone());
        issue.invalidate_cache();
        self.nodes_by_id
            .insert(node_id, NodeTarget::IssueComment(repo_id, issue_number, idx));
        Some(comment)
    }

    pub fn create_pull(
        &mut self,
        repo_id: u64,
        title: &str,
        body: &str,
        head: &str,
        base: &str,
    ) -> Result<u64, (u16, String)> {
        let (head_sha, base_sha, owner_name) = {
            let repo = self
                .repos
                .get(&repo_id)
                .ok_or_else(|| (404u16, "Not Found".to_string()))?;
            let h = repo.resolve_ref_oid(Some(head));
            let b = repo.resolve_ref_oid(Some(base));
            match (h, b) {
                (Some(hs), Some(bs)) => {
                    for &pn in &repo.pull_order {
                        if let Some(existing) = repo.pulls.get(&pn) {
                            if existing.is_open && existing.head_ref == head && existing.base_ref == base {
                                return Err((
                                    422,
                                    format!("A pull request already exists for {}:{head}", repo.owner),
                                ));
                            }
                        }
                    }
                    (hs, bs, repo.owner.clone())
                }
                _ => {
                    let _ = &repo;
                    return Err((
                        422,
                        "Validation Failed: head or base branch not found".to_string(),
                    ));
                }
            }
        };
        let _ = owner_name;
        let (seq, iso, _) = self.next_stamp();
        let id = self.alloc_id();
        let repo = self.repos.get_mut(&repo_id).unwrap();
        let number = repo.next_number;
        repo.next_number += 1;
        let node_id = format!("PR_{id}");
        let pull = Pull {
            id,
            node_id: node_id.clone(),
            number,
            title: title.to_string(),
            body: body.to_string(),
            is_open: true,
            head_ref: head.to_string(),
            base_ref: base.to_string(),
            head_sha,
            base_sha,
            merged: false,
            merged_at: None,
            merge_commit_sha: None,
            user_login: VIEWER_LOGIN,
            user_id: VIEWER_ID,
            created_seq: seq,
            created_at: iso.clone(),
            updated_at: iso,
        };
        repo.pulls.insert(number, pull);
        repo.pull_order.push(number);
        self.nodes_by_id
            .insert(node_id, NodeTarget::PullRequest(repo_id, number));
        Ok(number)
    }

    pub fn merge_pull(
        &mut self,
        repo_id: u64,
        number: u64,
        commit_title: Option<&str>,
    ) -> Result<[u8; 20], (u16, String)> {
        let (base_ref_full, base_tip, merged_files, default_msg) = {
            let repo = self
                .repos
                .get(&repo_id)
                .ok_or_else(|| (404u16, "Not Found".to_string()))?;
            let pr = repo
                .pulls
                .get(&number)
                .ok_or_else(|| (404u16, "Not Found".to_string()))?;
            if !pr.is_open || pr.merged {
                return Err((405, "Pull Request is not mergeable".to_string()));
            }
            let base_full = format!("refs/heads/{}", pr.base_ref);
            let b_tip = repo.refs.get(&base_full).copied().unwrap_or(pr.base_sha);
            let h_tip = repo
                .refs
                .get(&format!("refs/heads/{}", pr.head_ref))
                .copied()
                .unwrap_or(pr.head_sha);
            let merged_tree = repo
                .compute_three_way_merge(&b_tip, &h_tip)
                .ok_or_else(|| (405, "Pull Request is not mergeable: merge conflict".to_string()))?;
            (base_full, b_tip, merged_tree, format!("{} (#{number})", pr.title))
        };

        let (_seq, iso, epoch_sec) = self.next_stamp();
        let repo = self.repos.get_mut(&repo_id).unwrap();
        let tree_oid = repo.write_tree_from_flat(&merged_files);
        let msg = commit_title.unwrap_or(&default_msg);
        let author = format!("{VIEWER_NAME} <{VIEWER_EMAIL}>");
        let commit_bytes = encode_commit_bytes(&tree_oid, &[base_tip], &author, epoch_sec, msg);
        let merge_sha = repo.put_object_bytes(ObjKind::Commit, commit_bytes);
        repo.refs.insert(base_ref_full, merge_sha);
        repo.updated_at = iso.clone();
        repo.invalidate_git_caches();

        let pr = repo.pulls.get_mut(&number).unwrap();
        pr.is_open = false;
        pr.merged = true;
        pr.merged_at = Some(iso.clone());
        pr.merge_commit_sha = Some(merge_sha);
        pr.updated_at = iso;
        Ok(merge_sha)
    }

    #[inline]
    pub fn apply_single_push_command(
        &mut self,
        repo_id: u64,
        cmd: &PushCommandRef<'_>,
    ) -> (bool, &'static str) {
        let Some(repo) = self.repos.get_mut(&repo_id) else {
            return (false, "rejected");
        };
        let current_oid = repo.refs.get(cmd.ref_name).copied().unwrap_or(ZERO_OID);
        if cmd.new_oid == ZERO_OID {
            if current_oid == ZERO_OID || (cmd.old_oid != ZERO_OID && current_oid != cmd.old_oid) {
                return (false, "stale old oid");
            }
            repo.refs.remove(cmd.ref_name);
            repo.invalidate_git_caches();
            return (true, "");
        }

        let Some(target_kind) = repo.objects.get(&cmd.new_oid).map(|o| o.kind) else {
            return (false, "missing object");
        };

        if current_oid == ZERO_OID {
            if cmd.old_oid != ZERO_OID {
                return (false, "non-fast-forward");
            }
            repo.refs.insert(cmd.ref_name.to_string(), cmd.new_oid);
            repo.invalidate_git_caches();
            return (true, "");
        }

        if cmd.old_oid != ZERO_OID && cmd.old_oid != current_oid {
            return (false, "non-fast-forward");
        }

        if target_kind == ObjKind::Commit && !repo.is_ancestor(&current_oid, &cmd.new_oid) {
            return (false, "non-fast-forward");
        }

        if let Some(slot) = repo.refs.get_mut(cmd.ref_name) {
            *slot = cmd.new_oid;
        } else {
            repo.refs.insert(cmd.ref_name.to_string(), cmd.new_oid);
        }
        repo.invalidate_git_caches();
        (true, "")
    }

    pub fn apply_push_commands_ref(
        &mut self,
        repo_id: u64,
        commands: &[PushCommandRef<'_>],
    ) -> Vec<(bool, &'static str)> {
        let Some(repo) = self.repos.get_mut(&repo_id) else {
            return Vec::new();
        };
        let mut results = Vec::with_capacity(commands.len());
        let mut mutated = false;

        for cmd in commands {
            let current_oid = repo.refs.get(cmd.ref_name).copied().unwrap_or(ZERO_OID);
            if cmd.new_oid == ZERO_OID {
                if current_oid == ZERO_OID || (cmd.old_oid != ZERO_OID && current_oid != cmd.old_oid) {
                    results.push((false, "stale old oid"));
                    continue;
                }
                repo.refs.remove(cmd.ref_name);
                mutated = true;
                results.push((true, ""));
                continue;
            }

            let Some(target_kind) = repo.objects.get(&cmd.new_oid).map(|o| o.kind) else {
                results.push((false, "missing object"));
                continue;
            };

            if current_oid == ZERO_OID {
                if cmd.old_oid != ZERO_OID {
                    results.push((false, "non-fast-forward"));
                    continue;
                }
                repo.refs.insert(cmd.ref_name.to_string(), cmd.new_oid);
                mutated = true;
                results.push((true, ""));
                continue;
            }

            if cmd.old_oid != ZERO_OID && cmd.old_oid != current_oid {
                results.push((false, "non-fast-forward"));
                continue;
            }

            if target_kind == ObjKind::Commit && !repo.is_ancestor(&current_oid, &cmd.new_oid) {
                results.push((false, "non-fast-forward"));
                continue;
            }

            if let Some(slot) = repo.refs.get_mut(cmd.ref_name) {
                *slot = cmd.new_oid;
            } else {
                repo.refs.insert(cmd.ref_name.to_string(), cmd.new_oid);
            }
            mutated = true;
            results.push((true, ""));
        }

        if mutated {
            repo.invalidate_git_caches();
        }
        results
    }

    pub fn read_contents(
        &self,
        repo_id: u64,
        rel_path: &str,
        ref_param: Option<&str>,
    ) -> Option<ReadContentsResult> {
        let repo = self.repos.get(&repo_id)?;
        let commit_oid = repo.resolve_ref_oid(ref_param)?;
        let commit_obj = repo.objects.get(&commit_oid)?;
        if commit_obj.kind != ObjKind::Commit {
            return None;
        }
        let mut cur_oid = commit_obj.tree_oid?;
        let clean = rel_path.trim_matches('/');
        let segs: Vec<&str> = if clean.is_empty() {
            Vec::new()
        } else {
            clean.split('/').filter(|s| !s.is_empty()).collect()
        };

        for (i, &seg) in segs.iter().enumerate() {
            let tree_obj = repo.objects.get(&cur_oid)?;
            if tree_obj.kind != ObjKind::Tree {
                return None;
            }
            let entries = parse_tree_entries(&tree_obj.data).ok()?;
            let item = entries.into_iter().find(|e| e.name == seg)?;
            if i + 1 == segs.len() {
                if item.mode == "40000" || item.mode == "040000" {
                    cur_oid = item.oid;
                    break;
                }
                let blob = repo.objects.get(&item.oid)?;
                if blob.kind != ObjKind::Blob {
                    return None;
                }
                return Some(ReadContentsResult::File {
                    name: item.name,
                    path: clean.to_string(),
                    sha: oid_to_string(&item.oid),
                    size: blob.data.len(),
                    content_base64: base64_encode(&blob.data),
                });
            }
            if item.mode != "40000" && item.mode != "040000" {
                return None;
            }
            cur_oid = item.oid;
        }

        let dir_obj = repo.objects.get(&cur_oid)?;
        if dir_obj.kind != ObjKind::Tree {
            return None;
        }
        let items = parse_tree_entries(&dir_obj.data).ok()?;
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            let is_dir = item.mode == "40000" || item.mode == "040000";
            let size = if is_dir {
                0
            } else {
                repo.objects.get(&item.oid).map(|b| b.data.len()).unwrap_or(0)
            };
            let path = if clean.is_empty() {
                item.name.clone()
            } else {
                format!("{clean}/{}", item.name)
            };
            out.push(DirContentEntry {
                kind: if is_dir { "dir" } else { "file" },
                name: item.name,
                path,
                sha: oid_to_string(&item.oid),
                size,
            });
        }
        Some(ReadContentsResult::Dir(out))
    }

    pub fn put_content_file(
        &mut self,
        repo_id: u64,
        rel_path: &str,
        content_base64: &str,
        message: &str,
        branch: Option<&str>,
        expected_sha: Option<&str>,
    ) -> Result<(bool, String, String, usize), (u16, String)> {
        let clean = rel_path.trim_matches('/');
        if clean.is_empty() {
            return Err((422, "Invalid path".to_string()));
        }
        let decoded = base64_decode_lenient(content_base64.as_bytes())
            .ok_or_else(|| (422, "Invalid base64 content".to_string()))?;

        let (base_tip, full_ref, mut files, existing_oid) = {
            let repo = self
                .repos
                .get(&repo_id)
                .ok_or_else(|| (404u16, "Not Found".to_string()))?;
            let br = match branch {
                Some(b) if !b.is_empty() => b,
                _ => &repo.default_branch,
            };
            let fref = format!("refs/heads/{br}");
            let tip = repo
                .refs
                .get(&fref)
                .copied()
                .or_else(|| {
                    if br != repo.default_branch {
                        repo.refs.get(&format!("refs/heads/{}", repo.default_branch)).copied()
                    } else {
                        None
                    }
                });
            let files_map = match tip {
                Some(t) => repo.flatten_tree(&t),
                None => BTreeMap::new(),
            };
            let ex_oid = files_map.get(clean).map(|e| e.oid);
            if let Some(sha_str) = expected_sha {
                let Some(ex) = ex_oid else {
                    return Err((409, format!("{clean} does not match {sha_str}")));
                };
                if !oid_to_string(&ex).eq_ignore_ascii_case(sha_str) {
                    return Err((409, format!("{clean} does not match {sha_str}")));
                }
            } else if ex_oid.is_some() {
                return Err((
                    422,
                    format!("Invalid request: sha wasn't supplied for existing file {clean}"),
                ));
            }
            (tip, fref, files_map, ex_oid)
        };

        let (_seq, iso, epoch_sec) = self.next_stamp();
        let repo = self.repos.get_mut(&repo_id).unwrap();
        let size = decoded.len();
        let content_oid = repo.put_object_bytes(ObjKind::Blob, decoded.clone());
        files.insert(
            clean.to_string(),
            FlatFileEntry {
                mode: "100644".to_string(),
                oid: content_oid,
                data: decoded,
            },
        );
        let tree_oid = repo.write_tree_from_flat(&files);
        let msg = if message.is_empty() {
            format!("Update {clean}")
        } else {
            message.to_string()
        };
        let parents: Vec<[u8; 20]> = base_tip.into_iter().collect();
        let author = format!("{VIEWER_NAME} <{VIEWER_EMAIL}>");
        let commit_bytes = encode_commit_bytes(&tree_oid, &parents, &author, epoch_sec, &msg);
        let commit_oid = repo.put_object_bytes(ObjKind::Commit, commit_bytes);
        repo.refs.insert(full_ref, commit_oid);
        repo.updated_at = iso;
        repo.invalidate_git_caches();

        Ok((
            existing_oid.is_none(),
            oid_to_string(&content_oid),
            oid_to_string(&commit_oid),
            size,
        ))
    }

    pub fn delete_content_file(
        &mut self,
        repo_id: u64,
        rel_path: &str,
        message: &str,
        expected_sha: &str,
        branch: Option<&str>,
    ) -> Result<String, (u16, String)> {
        let clean = rel_path.trim_matches('/');
        let (base_tip, full_ref, mut files) = {
            let repo = self
                .repos
                .get(&repo_id)
                .ok_or_else(|| (404u16, "Not Found".to_string()))?;
            let br = match branch {
                Some(b) if !b.is_empty() => b,
                _ => &repo.default_branch,
            };
            let fref = format!("refs/heads/{br}");
            let tip = repo
                .refs
                .get(&fref)
                .copied()
                .ok_or_else(|| (404u16, "Not Found".to_string()))?;
            let files_map = repo.flatten_tree(&tip);
            let existing = files_map
                .get(clean)
                .ok_or_else(|| (404u16, "Not Found".to_string()))?;
            if !oid_to_string(&existing.oid).eq_ignore_ascii_case(expected_sha) {
                return Err((409, format!("{clean} does not match {expected_sha}")));
            }
            (tip, fref, files_map)
        };
        files.remove(clean);
        let (_seq, iso, epoch_sec) = self.next_stamp();
        let repo = self.repos.get_mut(&repo_id).unwrap();
        let tree_oid = repo.write_tree_from_flat(&files);
        let msg = if message.is_empty() {
            format!("Delete {clean}")
        } else {
            message.to_string()
        };
        let author = format!("{VIEWER_NAME} <{VIEWER_EMAIL}>");
        let commit_bytes = encode_commit_bytes(&tree_oid, &[base_tip], &author, epoch_sec, &msg);
        let commit_oid = repo.put_object_bytes(ObjKind::Commit, commit_bytes);
        repo.refs.insert(full_ref, commit_oid);
        repo.updated_at = iso;
        repo.invalidate_git_caches();
        Ok(oid_to_string(&commit_oid))
    }
}

pub struct ForgeStore {
    pub inner: RwLock<StoreInner>,
    pub read_epoch: AtomicU64,
    pub git_epoch: AtomicU64,
}

impl ForgeStore {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(StoreInner::new()),
            read_epoch: AtomicU64::new(1),
            git_epoch: AtomicU64::new(1),
        }
    }

    #[inline]
    pub fn bump_read_epoch(&self) {
        self.read_epoch.fetch_add(1, Ordering::Release);
    }

    #[inline]
    pub fn bump_git_epoch(&self) {
        self.git_epoch.fetch_add(1, Ordering::Release);
    }

    #[inline]
    pub fn bump_git_epoch_val(&self) -> u64 {
        self.git_epoch.fetch_add(1, Ordering::AcqRel) + 1
    }
}
