use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

use crate::git_http::{try_handle_git_http, GitResponse};
use crate::graphql::handle_graphql;
use crate::mcp::handle_mcp;
use crate::pack::PackDecoder;
use crate::rest::{handle_rest_api, not_found_http, RestResponse};
use crate::store::{base64_decode_lenient, build_http_response, ForgeStore};

const WORKER_COUNT: usize = 64;
const MAX_TOTAL_WORKERS: usize = 160;
const WORKER_STACK_BYTES: usize = 512 * 1024;
const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;
const HEALTHZ_HTTP: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nX-GitHub-Request-Id: 1\r\n\r\n{\"ok\":true}";
const HEALTHZ_HEAD_HTTP: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nX-GitHub-Request-Id: 1\r\n\r\n";

struct QueueState {
    conns: VecDeque<TcpStream>,
    idle_workers: usize,
    shutdown: bool,
}

pub struct AppContext {
    pub store: ForgeStore,
    pub expected_token: String,
    pub expected_bearer: Vec<u8>,
    pub err_auth_http: Vec<u8>,
    pub err_auth_git_http: Vec<u8>,
    queue: Mutex<QueueState>,
    cv: Condvar,
    total_workers: AtomicUsize,
    shutdown_flag: AtomicBool,
}

impl AppContext {
    pub fn new(token: String) -> Arc<Self> {
        let trimmed = token.trim().to_string();
        let expected_bearer = if trimmed.is_empty() {
            Vec::new()
        } else {
            format!("Bearer {trimmed}").into_bytes()
        };
        let auth_body = br#"{"message":"Requires authentication"}"#;
        let err_auth_http = build_http_response(
            b"HTTP/1.1 401 Unauthorized",
            b"application/json",
            b"",
            auth_body,
        );
        let err_auth_git_http = build_http_response(
            b"HTTP/1.1 401 Unauthorized",
            b"application/json",
            b"WWW-Authenticate: Basic realm=\"GitHub Forge\"\r\n",
            auth_body,
        );
        Arc::new(Self {
            store: ForgeStore::new(),
            expected_token: trimmed,
            expected_bearer,
            err_auth_http,
            err_auth_git_http,
            queue: Mutex::new(QueueState {
                conns: VecDeque::with_capacity(128),
                idle_workers: 0,
                shutdown: false,
            }),
            cv: Condvar::new(),
            total_workers: AtomicUsize::new(0),
            shutdown_flag: AtomicBool::new(false),
        })
    }

    pub fn spawn_pool(self: &Arc<Self>) {
        for _ in 0..WORKER_COUNT {
            let ctx = Arc::clone(self);
            ctx.total_workers.fetch_add(1, Ordering::Relaxed);
            thread::Builder::new()
                .name("forge-worker".to_string())
                .stack_size(WORKER_STACK_BYTES)
                .spawn(move || worker_loop(ctx))
                .expect("spawn worker thread");
        }
    }

    pub fn dispatch_conn(self: &Arc<Self>, stream: TcpStream) {
        let mut g = self.queue.lock().unwrap();
        let should_spawn = g.idle_workers <= g.conns.len()
            && self.total_workers.load(Ordering::Relaxed) < MAX_TOTAL_WORKERS;
        if should_spawn {
            drop(g);
            let ctx = Arc::clone(self);
            let ctx_sub = Arc::clone(self);
            ctx_sub.total_workers.fetch_add(1, Ordering::Relaxed);
            let spawned = thread::Builder::new()
                .name("forge-overflow".to_string())
                .stack_size(WORKER_STACK_BYTES)
                .spawn(move || {
                    overflow_conn_run(&ctx, stream);
                    ctx.total_workers.fetch_sub(1, Ordering::Relaxed);
                });
            if spawned.is_err() {
                ctx_sub.total_workers.fetch_sub(1, Ordering::Relaxed);
            }
            return;
        }
        g.conns.push_back(stream);
        self.cv.notify_one();
    }

    pub fn run_accept_loop(self: &Arc<Self>, listener: TcpListener) {
        for incoming in listener.incoming() {
            if self.shutdown_flag.load(Ordering::Relaxed) {
                break;
            }
            if let Ok(stream) = incoming {
                self.dispatch_conn(stream);
            }
        }
    }

    pub fn signal_shutdown(&self) {
        self.shutdown_flag.store(true, Ordering::Release);
        let mut g = self.queue.lock().unwrap();
        g.shutdown = true;
        self.cv.notify_all();
    }
}

#[derive(Clone)]
enum L1Bytes {
    Static(&'static [u8]),
    Arc(Arc<Vec<u8>>),
}

impl L1Bytes {
    #[inline]
    fn as_slice(&self) -> &[u8] {
        match self {
            L1Bytes::Static(s) => s,
            L1Bytes::Arc(a) => a,
        }
    }
}

struct GitPostSlot {
    epoch: u64,
    raw_req: Vec<u8>,
    target: Vec<u8>,
    body: Vec<u8>,
    resp: Option<L1Bytes>,
}

impl GitPostSlot {
    fn empty() -> Self {
        Self {
            epoch: 0,
            raw_req: Vec::new(),
            target: Vec::new(),
            body: Vec::new(),
            resp: None,
        }
    }
}

struct WorkerL1Cache {
    get_epoch: u64,
    get_is_git: bool,
    get_is_v2: bool,
    raw_get_req: Vec<u8>,
    get_path: Vec<u8>,
    get_resp: Option<L1Bytes>,
    git_post: [GitPostSlot; 2],
    git_post_next: usize,
}

impl WorkerL1Cache {
    fn new() -> Self {
        Self {
            get_epoch: 0,
            get_is_git: false,
            get_is_v2: false,
            raw_get_req: Vec::new(),
            get_path: Vec::with_capacity(96),
            get_resp: None,
            git_post: [GitPostSlot::empty(), GitPostSlot::empty()],
            git_post_next: 0,
        }
    }
}

fn worker_loop(ctx: Arc<AppContext>) {
    let mut decoder = PackDecoder::new();
    let mut read_buf = vec![0u8; 16 * 1024];
    let mut chunk_buf = Vec::with_capacity(4096);
    let mut body_scratch = Vec::with_capacity(2048);
    let mut write_buf = Vec::with_capacity(8192);
    let mut l1 = WorkerL1Cache::new();

    loop {
        let stream = {
            let mut g = ctx.queue.lock().unwrap();
            g.idle_workers += 1;
            while g.conns.is_empty() && !g.shutdown {
                g = ctx.cv.wait(g).unwrap();
            }
            g.idle_workers -= 1;
            if g.shutdown && g.conns.is_empty() {
                return;
            }
            match g.conns.pop_front() {
                Some(s) => s,
                None => continue,
            }
        };

        handle_connection(
            &ctx,
            stream,
            &mut decoder,
            &mut read_buf,
            &mut chunk_buf,
            &mut body_scratch,
            &mut write_buf,
            &mut l1,
        );
    }
}

fn overflow_conn_run(ctx: &Arc<AppContext>, stream: TcpStream) {
    let mut decoder = PackDecoder::new();
    let mut read_buf = vec![0u8; 16 * 1024];
    let mut chunk_buf = Vec::with_capacity(4096);
    let mut body_scratch = Vec::with_capacity(2048);
    let mut write_buf = Vec::with_capacity(8192);
    let mut l1 = WorkerL1Cache::new();
    handle_connection(
        ctx,
        stream,
        &mut decoder,
        &mut read_buf,
        &mut chunk_buf,
        &mut body_scratch,
        &mut write_buf,
        &mut l1,
    );
}

#[inline]
fn find_header_end(buf: &[u8]) -> Option<usize> {
    let mut pos = 0usize;
    while pos + 3 < buf.len() {
        let Some(r) = memchr::memchr(b'\r', &buf[pos..buf.len() - 3]) else {
            return None;
        };
        let i = pos + r;
        if &buf[i..i + 4] == b"\r\n\r\n" {
            return Some(i);
        }
        pos = i + 1;
    }
    None
}

#[inline]
fn is_authorized_slow(auth_val: &[u8], expected: &str) -> bool {
    if expected.is_empty() {
        return false;
    }
    let Ok(s) = std::str::from_utf8(auth_val) else {
        return false;
    };
    let trimmed = s.trim();
    let Some(sp) = trimmed.find(' ') else {
        return false;
    };
    let scheme = &trimmed[..sp];
    let cred = trimmed[sp + 1..].trim();
    if scheme.eq_ignore_ascii_case("bearer") || scheme.eq_ignore_ascii_case("token") {
        return cred == expected;
    }
    if scheme.eq_ignore_ascii_case("basic") {
        if let Some(decoded) = base64_decode_lenient(cred.as_bytes()) {
            if let Ok(text) = std::str::from_utf8(&decoded) {
                return match text.split_once(':') {
                    Some((user, pass)) => pass == expected || (pass.is_empty() && user == expected),
                    None => text == expected,
                };
            }
        }
    }
    false
}

fn contains_ascii_ci(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
}

fn handle_connection(
    ctx: &Arc<AppContext>,
    mut stream: TcpStream,
    decoder: &mut PackDecoder,
    read_buf: &mut Vec<u8>,
    chunk_buf: &mut Vec<u8>,
    body_scratch: &mut Vec<u8>,
    write_buf: &mut Vec<u8>,
    l1: &mut WorkerL1Cache,
) {
    let _ = stream.set_nodelay(true);

    let mut filled = 0usize;

    loop {
        if filled == 0 {
            match stream.read(&mut read_buf[..]) {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    filled = n;
                    if n <= 4096 {
                        if read_buf[0] == b'G'
                            && n == l1.raw_get_req.len()
                            && &read_buf[..n] == l1.raw_get_req.as_slice()
                        {
                            if let Some(resp) = &l1.get_resp {
                                let cur_epoch = if l1.get_is_git {
                                    ctx.store.git_epoch.load(Ordering::Acquire)
                                } else {
                                    ctx.store.read_epoch.load(Ordering::Acquire)
                                };
                                if cur_epoch == l1.get_epoch {
                                    if stream.write_all(resp.as_slice()).is_err() {
                                        return;
                                    }
                                    filled = 0;
                                    continue;
                                }
                            }
                        } else if read_buf[0] == b'P' {
                            let cur_git_epoch = ctx.store.git_epoch.load(Ordering::Acquire);
                            let mut hit_raw: Option<&[u8]> = None;
                            for slot in &l1.git_post {
                                if slot.epoch == cur_git_epoch
                                    && n == slot.raw_req.len()
                                    && &read_buf[..n] == slot.raw_req.as_slice()
                                {
                                    if let Some(r) = &slot.resp {
                                        hit_raw = Some(r.as_slice());
                                        break;
                                    }
                                }
                            }
                            if let Some(bytes) = hit_raw {
                                if stream.write_all(bytes).is_err() {
                                    return;
                                }
                                filled = 0;
                                continue;
                            }
                        }
                    }
                }
            }
        }

        let header_end = loop {
            if let Some(end) = find_header_end(&read_buf[..filled]) {
                break end;
            }
            if filled >= 256 * 1024 {
                return;
            }
            if filled == read_buf.len() {
                read_buf.resize(read_buf.len() * 2, 0);
            }
            match stream.read(&mut read_buf[filled..]) {
                Ok(0) | Err(_) => return,
                Ok(n) => filled += n,
            }
        };

        let (
            method_r,
            target_r,
            content_len,
            is_chunked,
            expect_100,
            conn_close,
            auth_r,
            git_proto_r,
            host_hdr_r,
            body_start,
        ) = {
            let header_block = &read_buf[..header_end];
            let line_end = memchr::memchr(b'\r', header_block).unwrap_or(header_block.len());
            let req_line = &header_block[..line_end];
            let Some(sp1) = memchr::memchr(b' ', req_line) else {
                return;
            };
            let rest_rl = &req_line[sp1 + 1..];
            let Some(sp2_rel) = memchr::memchr(b' ', rest_rl) else {
                return;
            };
            let sp2 = sp1 + 1 + sp2_rel;
            let method_r = (0usize, sp1);
            let target_r = (sp1 + 1, sp2);
            let version_b = &req_line[sp2 + 1..];

            let mut content_len: usize = 0;
            let mut is_chunked = false;
            let mut expect_100 = false;
            let mut conn_close = version_b == b"HTTP/1.0";
            let mut auth_r: Option<(usize, usize)> = None;
            let mut git_proto_r: Option<(usize, usize)> = None;
            let mut host_hdr_r: Option<(usize, usize)> = None;

            let mut cur = if line_end + 2 <= header_block.len() {
                line_end + 2
            } else {
                header_block.len()
            };
            while cur < header_block.len() {
                let next_cr = memchr::memchr(b'\r', &header_block[cur..])
                    .map(|r| cur + r)
                    .unwrap_or(header_block.len());
                let hline = &header_block[cur..next_cr];
                let hline_base = cur;
                cur = (next_cr + 2).min(header_block.len());

                let Some(colon) = memchr::memchr(b':', hline) else {
                    continue;
                };
                let hname = &hline[..colon];
                let raw_val = &hline[colon + 1..];
                let mut v_start = 0usize;
                let mut v_end = raw_val.len();
                while v_start < v_end && raw_val[v_start].is_ascii_whitespace() {
                    v_start += 1;
                }
                while v_end > v_start && raw_val[v_end - 1].is_ascii_whitespace() {
                    v_end -= 1;
                }
                let hval = &raw_val[v_start..v_end];
                let abs_start = hline_base + colon + 1 + v_start;
                let abs_end = hline_base + colon + 1 + v_end;

                if hname.is_empty() {
                    continue;
                }
                match (hname.len(), hname[0] | 0x20) {
                    (13, b'a') if hname.eq_ignore_ascii_case(b"authorization") => {
                        auth_r = Some((abs_start, abs_end));
                    }
                    (14, b'c') if hname.eq_ignore_ascii_case(b"content-length") => {
                        let mut cl = 0usize;
                        let mut ok = !hval.is_empty();
                        for &b in hval {
                            if b.is_ascii_digit() {
                                cl = cl.saturating_mul(10).saturating_add((b - b'0') as usize);
                            } else {
                                ok = false;
                                break;
                            }
                        }
                        if ok {
                            content_len = cl;
                        }
                    }
                    (17, b't') if hname.eq_ignore_ascii_case(b"transfer-encoding") => {
                        if contains_ascii_ci(hval, b"chunked") {
                            is_chunked = true;
                        }
                    }
                    (10, b'c') if hname.eq_ignore_ascii_case(b"connection") => {
                        if contains_ascii_ci(hval, b"close") {
                            conn_close = true;
                        } else if conn_close && contains_ascii_ci(hval, b"keep-alive") {
                            conn_close = false;
                        }
                    }
                    (12, b'g') if hname.eq_ignore_ascii_case(b"git-protocol") => {
                        git_proto_r = Some((abs_start, abs_end));
                    }
                    (4, b'h') if hname.eq_ignore_ascii_case(b"host") => {
                        host_hdr_r = Some((abs_start, abs_end));
                    }
                    (6, b'e') if hname.eq_ignore_ascii_case(b"expect") => {
                        if contains_ascii_ci(hval, b"100-continue") {
                            expect_100 = true;
                        }
                    }
                    _ => {}
                }
            }
            (
                method_r,
                target_r,
                content_len,
                is_chunked,
                expect_100,
                conn_close,
                auth_r,
                git_proto_r,
                host_hdr_r,
                header_end + 4,
            )
        };

        if expect_100 && stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").is_err() {
            return;
        }

        let (total_consumed, body_is_chunked): (usize, bool) = if is_chunked {
            chunk_buf.clear();
            let mut pos = body_start;
            loop {
                let crlf_pos = loop {
                    if let Some(p) = read_buf[pos..filled].windows(2).position(|w| w == b"\r\n") {
                        break pos + p;
                    }
                    if filled == read_buf.len() {
                        if read_buf.len() >= MAX_BODY_BYTES {
                            return;
                        }
                        read_buf.resize((read_buf.len() * 2).min(MAX_BODY_BYTES), 0);
                    }
                    match stream.read(&mut read_buf[filled..]) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => filled += n,
                    }
                };
                let size_slice = &read_buf[pos..crlf_pos];
                let hex_part = match memchr::memchr(b';', size_slice) {
                    Some(sc) => &size_slice[..sc],
                    None => size_slice,
                };
                let Ok(hex_str) = std::str::from_utf8(hex_part.trim_ascii()) else {
                    return;
                };
                let Ok(chunk_len) = usize::from_str_radix(hex_str, 16) else {
                    return;
                };
                pos = crlf_pos + 2;
                if chunk_len == 0 {
                    while pos + 2 > filled {
                        match stream.read(&mut read_buf[filled..]) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => filled += n,
                        }
                    }
                    if &read_buf[pos..pos + 2] == b"\r\n" {
                        pos += 2;
                    } else {
                        while !read_buf[pos..filled].windows(4).any(|w| w == b"\r\n\r\n") {
                            if filled == read_buf.len() {
                                return;
                            }
                            match stream.read(&mut read_buf[filled..]) {
                                Ok(0) | Err(_) => return,
                                Ok(n) => filled += n,
                            }
                        }
                        let end_tr = read_buf[pos..filled]
                            .windows(4)
                            .position(|w| w == b"\r\n\r\n")
                            .unwrap();
                        pos += end_tr + 4;
                    }
                    break;
                }
                if chunk_buf.len() + chunk_len > MAX_BODY_BYTES {
                    return;
                }
                let need_end = pos + chunk_len + 2;
                if need_end > read_buf.len() {
                    read_buf.resize(need_end.max(read_buf.len() * 2), 0);
                }
                while filled < need_end {
                    match stream.read(&mut read_buf[filled..]) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => filled += n,
                    }
                }
                chunk_buf.extend_from_slice(&read_buf[pos..pos + chunk_len]);
                pos = need_end;
            }
            (pos, true)
        } else {
            if content_len > MAX_BODY_BYTES {
                return;
            }
            let total_req = body_start + content_len;
            if total_req > read_buf.len() {
                read_buf.resize(total_req.next_power_of_two(), 0);
            }
            while filled < total_req {
                match stream.read(&mut read_buf[filled..]) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => filled += n,
                }
            }
            (total_req, false)
        };

        let method_b = &read_buf[method_r.0..method_r.1];
        let target_b = &read_buf[target_r.0..target_r.1];
        let auth_val: &[u8] = match auth_r {
            Some((s, e)) => &read_buf[s..e],
            None => b"",
        };
        let git_proto = git_proto_r.and_then(|(s, e)| std::str::from_utf8(&read_buf[s..e]).ok());
        let host_hdr = host_hdr_r.and_then(|(s, e)| std::str::from_utf8(&read_buf[s..e]).ok());

        // Fast keep-alive & worker L1 checks before locking or routing
        let req_is_v2 = git_proto
            .map(|h| contains_ascii_ci(h.as_bytes(), b"version=2"))
            .unwrap_or(false);
        if !ctx.expected_bearer.is_empty() && auth_val == ctx.expected_bearer.as_slice() {
            if method_b == b"GET" && target_b == l1.get_path.as_slice() {
                if let Some(resp) = &l1.get_resp {
                    let cur_epoch = if l1.get_is_git {
                        ctx.store.git_epoch.load(Ordering::Acquire)
                    } else {
                        ctx.store.read_epoch.load(Ordering::Acquire)
                    };
                    if cur_epoch == l1.get_epoch && (!l1.get_is_git || l1.get_is_v2 == req_is_v2) {
                        if stream.write_all(resp.as_slice()).is_err() {
                            return;
                        }
                        if conn_close {
                            return;
                        }
                        if total_consumed < filled {
                            read_buf.copy_within(total_consumed..filled, 0);
                            filled -= total_consumed;
                        } else {
                            filled = 0;
                        }
                        continue;
                    }
                }
            } else if method_b == b"POST" && target_b.ends_with(b"/git-upload-pack") {
                let body_slice_l1: &[u8] = if body_is_chunked {
                    chunk_buf.as_slice()
                } else {
                    &read_buf[body_start..body_start + content_len]
                };
                let cur_git_epoch = ctx.store.git_epoch.load(Ordering::Acquire);
                let mut hit_slice: Option<&[u8]> = None;
                for slot in &l1.git_post {
                    if slot.epoch == cur_git_epoch
                        && slot.target.as_slice() == target_b
                        && slot.body.as_slice() == body_slice_l1
                    {
                        if let Some(r) = &slot.resp {
                            hit_slice = Some(r.as_slice());
                            break;
                        }
                    }
                }
                if let Some(bytes) = hit_slice {
                    if stream.write_all(bytes).is_err() {
                        return;
                    }
                    if conn_close {
                        return;
                    }
                    if total_consumed < filled {
                        read_buf.copy_within(total_consumed..filled, 0);
                        filled -= total_consumed;
                    } else {
                        filled = 0;
                    }
                    continue;
                }
            }
        }

        let target_str = match std::str::from_utf8(target_b) {
            Ok(s) => s,
            Err(_) => return,
        };
        let (pathname, query) = match target_str.find('?') {
            Some(q) => (&target_str[..q], &target_str[q + 1..]),
            None => (target_str, ""),
        };
        let method_str = match std::str::from_utf8(method_b) {
            Ok(s) => s,
            Err(_) => return,
        };

        if pathname == "/healthz" && (method_b == b"GET" || method_b == b"HEAD") {
            let bytes = if method_b == b"HEAD" { HEALTHZ_HEAD_HTTP } else { HEALTHZ_HTTP };
            if stream.write_all(bytes).is_err() {
                return;
            }
        } else {
            let auth_ok = (!ctx.expected_bearer.is_empty() && auth_val == ctx.expected_bearer.as_slice())
                || is_authorized_slow(auth_val, &ctx.expected_token);

            if !auth_ok {
                let err_resp = if pathname.contains(".git/") {
                    &ctx.err_auth_git_http
                } else {
                    &ctx.err_auth_http
                };
                if stream.write_all(err_resp).is_err() {
                    return;
                }
            } else {
                let body_slice: &[u8] = if body_is_chunked {
                    chunk_buf.as_slice()
                } else {
                    &read_buf[body_start..body_start + content_len]
                };
                let cache_raw = !conn_close && !body_is_chunked && total_consumed <= 4096;

                write_buf.clear();
                if pathname == "/mcp" {
                    handle_mcp(&ctx.store, method_str, body_slice, write_buf);
                    if stream.write_all(write_buf).is_err() {
                        return;
                    }
                } else if pathname == "/api/graphql" {
                    handle_graphql(&ctx.store, method_str, body_slice, write_buf);
                    if stream.write_all(write_buf).is_err() {
                        return;
                    }
                } else if pathname == "/api/v3" || pathname.starts_with("/api/v3/") {
                    match handle_rest_api(
                        &ctx.store,
                        method_str,
                        pathname,
                        query,
                        host_hdr,
                        body_slice,
                        body_scratch,
                        write_buf,
                    ) {
                        RestResponse::Static(slice) => {
                            if stream.write_all(slice).is_err() {
                                return;
                            }
                        }
                        RestResponse::Cached(arc) => {
                            if method_b == b"GET" {
                                l1.get_epoch = ctx.store.read_epoch.load(Ordering::Acquire);
                                l1.get_is_git = false;
                                l1.get_is_v2 = false;
                                l1.get_path.clear();
                                l1.get_path.extend_from_slice(target_b);
                                l1.get_resp = Some(L1Bytes::Arc(arc.clone()));
                                if cache_raw {
                                    l1.raw_get_req.clear();
                                    l1.raw_get_req.extend_from_slice(&read_buf[..total_consumed]);
                                } else {
                                    l1.raw_get_req.clear();
                                }
                            }
                            if stream.write_all(&arc).is_err() {
                                return;
                            }
                        }
                        RestResponse::Written => {
                            if stream.write_all(write_buf).is_err() {
                                return;
                            }
                        }
                    }
                } else if let Some(git_res) = try_handle_git_http(
                    &ctx.store,
                    decoder,
                    method_str,
                    pathname,
                    query,
                    git_proto,
                    body_slice,
                    write_buf,
                ) {
                    match git_res {
                        GitResponse::Static(slice) => {
                            if method_b == b"GET" {
                                l1.get_epoch = ctx.store.git_epoch.load(Ordering::Acquire);
                                l1.get_is_git = true;
                                l1.get_is_v2 = req_is_v2;
                                l1.get_path.clear();
                                l1.get_path.extend_from_slice(target_b);
                                l1.get_resp = Some(L1Bytes::Static(slice));
                                if cache_raw {
                                    l1.raw_get_req.clear();
                                    l1.raw_get_req.extend_from_slice(&read_buf[..total_consumed]);
                                } else {
                                    l1.raw_get_req.clear();
                                }
                            }
                            if stream.write_all(slice).is_err() {
                                return;
                            }
                        }
                        GitResponse::Cached(arc) => {
                            if method_b == b"GET" {
                                l1.get_epoch = ctx.store.git_epoch.load(Ordering::Acquire);
                                l1.get_is_git = true;
                                l1.get_is_v2 = req_is_v2;
                                l1.get_path.clear();
                                l1.get_path.extend_from_slice(target_b);
                                l1.get_resp = Some(L1Bytes::Arc(arc.clone()));
                                if cache_raw {
                                    l1.raw_get_req.clear();
                                    l1.raw_get_req.extend_from_slice(&read_buf[..total_consumed]);
                                } else {
                                    l1.raw_get_req.clear();
                                }
                            } else if method_b == b"POST" && target_b.ends_with(b"/git-upload-pack") {
                                let idx = l1.git_post_next;
                                l1.git_post_next = (idx + 1) & 1;
                                let slot = &mut l1.git_post[idx];
                                slot.epoch = ctx.store.git_epoch.load(Ordering::Acquire);
                                slot.target.clear();
                                slot.target.extend_from_slice(target_b);
                                slot.body.clear();
                                slot.body.extend_from_slice(body_slice);
                                slot.resp = Some(L1Bytes::Arc(arc.clone()));
                                if cache_raw {
                                    slot.raw_req.clear();
                                    slot.raw_req.extend_from_slice(&read_buf[..total_consumed]);
                                } else {
                                    slot.raw_req.clear();
                                }
                            }
                            if stream.write_all(&arc).is_err() {
                                return;
                            }
                        }
                        GitResponse::PushWritten { updated_receive_adv } => {
                            if stream.write_all(write_buf).is_err() {
                                return;
                            }
                            if let Some((adv_arc, new_epoch)) = updated_receive_adv {
                                if l1.get_is_git
                                    && l1
                                        .get_path
                                        .ends_with(b"/info/refs?service=git-receive-pack")
                                {
                                    if let (Some(p1), Some(p2)) = (
                                        target_b.windows(5).position(|w| w == b".git/"),
                                        l1.get_path.windows(5).position(|w| w == b".git/"),
                                    ) {
                                        if target_b[..p1] == l1.get_path[..p2] {
                                            l1.get_epoch = new_epoch;
                                            l1.get_resp = Some(L1Bytes::Arc(adv_arc));
                                        }
                                    }
                                }
                            }
                        }
                        GitResponse::Written => {
                            if stream.write_all(write_buf).is_err() {
                                return;
                            }
                        }
                    }
                } else if stream.write_all(not_found_http()).is_err() {
                    return;
                }
            }
        }

        if conn_close {
            return;
        }
        if total_consumed < filled {
            read_buf.copy_within(total_consumed..filled, 0);
            filled -= total_consumed;
        } else {
            filled = 0;
        }
    }
}
