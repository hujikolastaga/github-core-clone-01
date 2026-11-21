use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, OnceLock};

use rustc_hash::FxHashSet;
use serde_json::Value;

use crate::sha1::{hex_to_oid, oid_to_string, ZERO_OID};
use crate::store::{
    build_http_response, cow_percent_decode, json_escape_into, parse_commit_message_and_author,
    percent_decode, write_issue_json_into, Comment, ForgeStore, Issue, Label, Pull,
    PullFileChange, ReadContentsResult, Repo, VIEWER_EMAIL, VIEWER_ID, VIEWER_LOGIN, VIEWER_NAME,
    VIEWER_NODE_ID,
};

static API_ROOT_HTTP: OnceLock<Vec<u8>> = OnceLock::new();
static API_META_HTTP: OnceLock<Vec<u8>> = OnceLock::new();
static NOT_FOUND_HTTP: OnceLock<Vec<u8>> = OnceLock::new();
static EMPTY_204_HTTP: &[u8] = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nX-GitHub-Request-Id: 1\r\n\r\n";

pub fn not_found_http() -> &'static [u8] {
    NOT_FOUND_HTTP.get_or_init(|| {
        build_http_response(
            b"HTTP/1.1 404 Not Found",
            b"application/json",
            b"",
            b"{\"message\":\"Not Found\"}",
        )
    })
}

fn api_root_http() -> &'static [u8] {
    API_ROOT_HTTP.get_or_init(|| {
        let body = br#"{"current_user_url":"/api/v3/user","user_repositories_url":"/api/v3/user/repos","repository_url":"/api/v3/repos/{owner}/{repo}","rate_limit_url":"/api/v3/rate_limit"}"#;
        build_http_response(
            b"HTTP/1.1 200 OK",
            b"application/json",
            b"X-OAuth-Scopes: repo, read:org\r\n",
            body,
        )
    })
}

fn api_meta_http() -> &'static [u8] {
    API_META_HTTP.get_or_init(|| {
        let body = br#"{"installed_version":"3.14.0","verifiable_password_authentication":false}"#;
        build_http_response(
            b"HTTP/1.1 200 OK",
            b"application/json",
            b"",
            body,
        )
    })
}

pub enum RestResponse {
    Static(&'static [u8]),
    Cached(Arc<Vec<u8>>),
    Written,
}

fn status_line_for(status: u16) -> &'static [u8] {
    match status {
        200 => b"HTTP/1.1 200 OK",
        201 => b"HTTP/1.1 201 Created",
        400 => b"HTTP/1.1 400 Bad Request",
        401 => b"HTTP/1.1 401 Unauthorized",
        404 => b"HTTP/1.1 404 Not Found",
        405 => b"HTTP/1.1 405 Method Not Allowed",
        409 => b"HTTP/1.1 409 Conflict",
        422 => b"HTTP/1.1 422 Unprocessable Entity",
        _ => b"HTTP/1.1 500 Internal Server Error",
    }
}

pub fn write_http_json(write_buf: &mut Vec<u8>, status: u16, extra_headers: &[u8], body: &[u8]) {
    let sl = status_line_for(status);
    let mut len_buf = itoa::Buffer::new();
    let len_str = len_buf.format(body.len());
    write_buf.reserve(sl.len() + extra_headers.len() + body.len() + 80);
    write_buf.extend_from_slice(sl);
    write_buf.extend_from_slice(b"\r\nContent-Type: application/json\r\nContent-Length: ");
    write_buf.extend_from_slice(len_str.as_bytes());
    write_buf.extend_from_slice(b"\r\nX-GitHub-Request-Id: 1\r\n");
    if !extra_headers.is_empty() {
        write_buf.extend_from_slice(extra_headers);
    }
    write_buf.extend_from_slice(b"\r\n");
    write_buf.extend_from_slice(body);
}

pub fn write_json_message(write_buf: &mut Vec<u8>, status: u16, msg: &str) {
    let mut body = Vec::with_capacity(msg.len() + 24);
    body.extend_from_slice(b"{\"message\":");
    json_escape_into(&mut body, msg);
    body.push(b'}');
    write_http_json(write_buf, status, b"", &body);
}

fn parse_ascii_uint(s: &str) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let mut n = 0u64;
    for &b in s.as_bytes() {
        if !b.is_ascii_digit() {
            return None;
        }
        n = n.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    if n > 0 { Some(n) } else { None }
}

fn query_param<'a>(query: &'a str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return Some(percent_decode(v));
            }
        }
    }
    None
}

fn parse_pos_usize_query(query: &str, key: &str, default: usize) -> usize {
    query_param(query, key)
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(default)
}

fn parse_json_object(body: &[u8]) -> Result<serde_json::Map<String, Value>, ()> {
    if body.is_empty() {
        return Ok(serde_json::Map::new());
    }
    match serde_json::from_slice::<Value>(body) {
        Ok(Value::Object(map)) => Ok(map),
        _ => Err(()),
    }
}

/// Fast-path zero-alloc parser for simple `{"title":"...","body":"..."}` JSON without escapes.
fn try_fast_parse_issue_json(body: &[u8]) -> Option<(&str, &str)> {
    if body.len() < 12 || body.contains(&b'\\') {
        return None;
    }
    let s = std::str::from_utf8(body).ok()?.trim();
    if !s.starts_with('{') || !s.ends_with('}') {
        return None;
    }
    let inner = s[1..s.len() - 1].as_bytes();
    let mut pos = 0usize;
    let mut title: Option<&str> = None;
    let mut issue_body: &str = "";
    while pos < inner.len() {
        while pos < inner.len() && (inner[pos].is_ascii_whitespace() || inner[pos] == b',') {
            pos += 1;
        }
        if pos >= inner.len() {
            break;
        }
        if inner[pos] != b'"' {
            return None;
        }
        pos += 1;
        let k_end = memchr::memchr(b'"', &inner[pos..])?;
        let key = &inner[pos..pos + k_end];
        pos += k_end + 1;
        while pos < inner.len() && inner[pos].is_ascii_whitespace() {
            pos += 1;
        }
        if pos >= inner.len() || inner[pos] != b':' {
            return None;
        }
        pos += 1;
        while pos < inner.len() && inner[pos].is_ascii_whitespace() {
            pos += 1;
        }
        if pos >= inner.len() || inner[pos] != b'"' {
            return None;
        }
        pos += 1;
        let v_end = memchr::memchr(b'"', &inner[pos..])?;
        let val = unsafe { std::str::from_utf8_unchecked(&inner[pos..pos + v_end]) };
        pos += v_end + 1;
        match key {
            b"title" => title = Some(val),
            b"body" => issue_body = val,
            _ => return None,
        }
    }
    title.map(|t| (t, issue_body))
}

pub fn write_repo_json_into(out: &mut Vec<u8>, repo: &Repo) {
    let mut ibuf = itoa::Buffer::new();
    out.extend_from_slice(b"{\"id\":");
    out.extend_from_slice(ibuf.format(repo.id).as_bytes());
    out.extend_from_slice(b",\"node_id\":");
    json_escape_into(out, &repo.node_id);
    out.extend_from_slice(b",\"name\":");
    json_escape_into(out, &repo.name);
    out.extend_from_slice(b",\"full_name\":");
    let full_name = format!("{}/{}", repo.owner, repo.name);
    json_escape_into(out, &full_name);
    out.extend_from_slice(b",\"private\":");
    out.extend_from_slice(if repo.private { b"true" } else { b"false" });
    out.extend_from_slice(b",\"owner\":{\"login\":");
    json_escape_into(out, &repo.owner);
    out.extend_from_slice(b",\"id\":");
    out.extend_from_slice(ibuf.format(VIEWER_ID).as_bytes());
    out.extend_from_slice(b",\"type\":\"User\"},\"description\":");
    json_escape_into(out, &repo.description);
    out.extend_from_slice(b",\"default_branch\":");
    json_escape_into(out, &repo.default_branch);
    out.extend_from_slice(b",\"has_issues\":true,\"created_at\":");
    json_escape_into(out, &repo.created_at);
    out.extend_from_slice(b",\"updated_at\":");
    json_escape_into(out, &repo.updated_at);
    out.push(b'}');
}

pub fn write_comment_json_into(out: &mut Vec<u8>, c: &Comment) {
    let mut ibuf = itoa::Buffer::new();
    out.extend_from_slice(b"{\"id\":");
    out.extend_from_slice(ibuf.format(c.id).as_bytes());
    out.extend_from_slice(b",\"node_id\":");
    json_escape_into(out, &c.node_id);
    out.extend_from_slice(b",\"body\":");
    json_escape_into(out, &c.body);
    out.extend_from_slice(b",\"user\":{\"login\":");
    json_escape_into(out, &c.user_login);
    out.extend_from_slice(b",\"id\":");
    out.extend_from_slice(ibuf.format(c.user_id).as_bytes());
    out.extend_from_slice(b",\"type\":\"User\"},\"created_at\":");
    json_escape_into(out, &c.created_at);
    out.extend_from_slice(b",\"updated_at\":");
    json_escape_into(out, &c.updated_at);
    out.push(b'}');
}

pub fn write_label_json_into(out: &mut Vec<u8>, l: &Label) {
    let mut ibuf = itoa::Buffer::new();
    out.extend_from_slice(b"{\"id\":");
    out.extend_from_slice(ibuf.format(l.id).as_bytes());
    out.extend_from_slice(b",\"node_id\":");
    json_escape_into(out, &l.node_id);
    out.extend_from_slice(b",\"name\":");
    json_escape_into(out, &l.name);
    out.extend_from_slice(b",\"color\":");
    json_escape_into(out, &l.color);
    out.extend_from_slice(b",\"description\":");
    json_escape_into(out, &l.description);
    out.push(b'}');
}

pub fn write_pull_json_into(out: &mut Vec<u8>, repo: &Repo, pr: &Pull) {
    let mut ibuf = itoa::Buffer::new();
    let head_tip = repo
        .refs
        .get(&format!("refs/heads/{}", pr.head_ref))
        .copied()
        .unwrap_or(pr.head_sha);
    let base_tip = repo
        .refs
        .get(&format!("refs/heads/{}", pr.base_ref))
        .copied()
        .unwrap_or(pr.base_sha);
    let head_hex = oid_to_string(&head_tip);
    let base_hex = oid_to_string(&base_tip);
    let head_label = format!("{}:{}", repo.owner, pr.head_ref);
    let base_label = format!("{}:{}", repo.owner, pr.base_ref);

    out.extend_from_slice(b"{\"id\":");
    out.extend_from_slice(ibuf.format(pr.id).as_bytes());
    out.extend_from_slice(b",\"node_id\":");
    json_escape_into(out, &pr.node_id);
    out.extend_from_slice(b",\"number\":");
    out.extend_from_slice(ibuf.format(pr.number).as_bytes());
    out.extend_from_slice(b",\"title\":");
    json_escape_into(out, &pr.title);
    out.extend_from_slice(b",\"body\":");
    json_escape_into(out, &pr.body);
    out.extend_from_slice(b",\"state\":\"");
    out.extend_from_slice(if pr.is_open { b"open" } else { b"closed" });
    out.extend_from_slice(b"\",\"merged\":");
    out.extend_from_slice(if pr.merged { b"true" } else { b"false" });
    out.extend_from_slice(b",\"merged_at\":");
    match &pr.merged_at {
        Some(ts) => json_escape_into(out, ts),
        None => out.extend_from_slice(b"null"),
    }
    out.extend_from_slice(b",\"merge_commit_sha\":");
    match &pr.merge_commit_sha {
        Some(sha) => json_escape_into(out, &oid_to_string(sha)),
        None => out.extend_from_slice(b"null"),
    }
    out.extend_from_slice(b",\"head\":{\"label\":");
    json_escape_into(out, &head_label);
    out.extend_from_slice(b",\"ref\":");
    json_escape_into(out, &pr.head_ref);
    out.extend_from_slice(b",\"sha\":");
    json_escape_into(out, &head_hex);
    out.extend_from_slice(b"},\"base\":{\"label\":");
    json_escape_into(out, &base_label);
    out.extend_from_slice(b",\"ref\":");
    json_escape_into(out, &pr.base_ref);
    out.extend_from_slice(b",\"sha\":");
    json_escape_into(out, &base_hex);
    out.extend_from_slice(b"},\"user\":{\"login\":");
    json_escape_into(out, &pr.user_login);
    out.extend_from_slice(b",\"id\":");
    out.extend_from_slice(ibuf.format(pr.user_id).as_bytes());
    out.extend_from_slice(b",\"type\":\"User\"},\"created_at\":");
    json_escape_into(out, &pr.created_at);
    out.extend_from_slice(b",\"updated_at\":");
    json_escape_into(out, &pr.updated_at);
    out.push(b'}');
}

fn list_repo_commits_json(repo: &Repo, sha_param: Option<&str>) -> Vec<u8> {
    let tip = repo.resolve_ref_oid(sha_param);
    let mut out = Vec::with_capacity(512);
    out.push(b'[');
    let Some(tip_oid) = tip else {
        out.push(b']');
        return out;
    };
    let mut seen: FxHashSet<[u8; 20]> = FxHashSet::default();
    let mut queue = VecDeque::new();
    queue.push_back(tip_oid);
    let mut emitted = 0usize;

    while let Some(oid) = queue.pop_front() {
        if emitted >= 100 {
            break;
        }
        if !seen.insert(oid) {
            continue;
        }
        let Some(obj) = repo.objects.get(&oid) else {
            continue;
        };
        if obj.kind != crate::sha1::ObjKind::Commit {
            continue;
        }
        let (msg, _author, parents) = parse_commit_message_and_author(&obj.data);
        if emitted > 0 {
            out.push(b',');
        }
        emitted += 1;
        out.extend_from_slice(b"{\"sha\":");
        json_escape_into(&mut out, &oid_to_string(&oid));
        out.extend_from_slice(b",\"commit\":{\"message\":");
        json_escape_into(&mut out, &msg);
        out.extend_from_slice(b",\"author\":{\"name\":");
        json_escape_into(&mut out, VIEWER_NAME);
        out.extend_from_slice(b",\"email\":");
        json_escape_into(&mut out, VIEWER_EMAIL);
        out.extend_from_slice(b",\"date\":");
        json_escape_into(&mut out, &repo.created_at);
        out.extend_from_slice(b"},\"committer\":{\"name\":");
        json_escape_into(&mut out, VIEWER_NAME);
        out.extend_from_slice(b",\"email\":");
        json_escape_into(&mut out, VIEWER_EMAIL);
        out.extend_from_slice(b",\"date\":");
        json_escape_into(&mut out, &repo.created_at);
        out.extend_from_slice(b"}},\"parents\":[");
        for (pi, p) in parents.iter().enumerate() {
            if pi > 0 {
                out.push(b',');
            }
            out.extend_from_slice(b"{\"sha\":");
            json_escape_into(&mut out, &oid_to_string(p));
            out.push(b'}');
            if !seen.contains(p) {
                queue.push_back(*p);
            }
        }
        out.extend_from_slice(b"]}");
    }
    out.push(b']');
    out
}

pub fn handle_rest_api(
    store: &ForgeStore,
    method: &str,
    pathname: &str,
    query: &str,
    host_header: Option<&str>,
    body: &[u8],
    body_scratch: &mut Vec<u8>,
    write_buf: &mut Vec<u8>,
) -> RestResponse {
    let sub = &pathname["/api/v3".len()..];

    // Hot path 1: GET /api/v3/repos/{owner}/{repo}/issues/{number}
    if method == "GET" {
        if let Some(after_repos) = sub.strip_prefix("/repos/") {
            if let Some(s1) = after_repos.find('/') {
                if let Some(s2_rel) = after_repos[s1 + 1..].find('/') {
                    let s2 = s1 + 1 + s2_rel;
                    if let Some(num_str) = after_repos[s2..].strip_prefix("/issues/") {
                        if let Some(num) = parse_ascii_uint(num_str) {
                            let owner = cow_percent_decode(&after_repos[..s1]);
                            let repo_name = cow_percent_decode(&after_repos[s1 + 1..s2]);
                            let cached_hit = {
                                let g = store.inner.read().unwrap();
                                g.get_repo(&owner, &repo_name)
                                    .and_then(|r| r.issues.get(&num))
                                    .and_then(|i| i.http_200_cache.clone())
                            };
                            if let Some(arc_http) = cached_hit {
                                return RestResponse::Cached(arc_http);
                            }
                            let mut g = store.inner.write().unwrap();
                            if let Some(repo) = g.get_repo_mut(&owner, &repo_name) {
                                if let Some(issue) = repo.issues.get_mut(&num) {
                                    let (_, http) = issue.ensure_json_and_http();
                                    return RestResponse::Cached(http);
                                }
                            }
                            return RestResponse::Static(not_found_http());
                        }
                    }
                }
            }
        }
    }

    // Hot path 2: POST /api/v3/repos/{owner}/{repo}/issues
    if method == "POST" && sub.ends_with("/issues") {
        if let Some(middle) = sub.strip_prefix("/repos/").and_then(|s| s.strip_suffix("/issues")) {
            if let Some(s1) = middle.find('/') {
                if !middle[s1 + 1..].contains('/') {
                    let owner = cow_percent_decode(&middle[..s1]);
                    let repo_name = cow_percent_decode(&middle[s1 + 1..]);

                    if let Some((fast_title, fast_body)) = try_fast_parse_issue_json(body) {
                        let mut g = store.inner.write().unwrap();
                        let Some(repo_id) = g.find_repo_id(&owner, &repo_name) else {
                            return RestResponse::Static(not_found_http());
                        };
                        let num = match g.create_issue(repo_id, fast_title, fast_body, None) {
                            Ok(n) => n,
                            Err((st, msg)) => {
                                write_json_message(write_buf, st, &msg);
                                return RestResponse::Written;
                            }
                        };
                        let issue = &g.repos.get(&repo_id).unwrap().issues[&num];
                        body_scratch.clear();
                        write_issue_json_into(body_scratch, issue);
                        write_http_json(write_buf, 201, b"", body_scratch);
                        return RestResponse::Written;
                    }

                    // Fallback to full JSON parser
                    let repo_id = {
                        let g = store.inner.read().unwrap();
                        match g.find_repo_id(&owner, &repo_name) {
                            Some(id) => id,
                            None => return RestResponse::Static(not_found_http()),
                        }
                    };
                    let Ok(obj) = parse_json_object(body) else {
                        write_json_message(write_buf, 400, "Problems parsing JSON");
                        return RestResponse::Written;
                    };
                    let Some(Value::String(title)) = obj.get("title") else {
                        write_json_message(write_buf, 422, "Validation Failed: title is required");
                        return RestResponse::Written;
                    };
                    let issue_body = match obj.get("body") {
                        Some(Value::String(b)) => b.as_str(),
                        _ => "",
                    };
                    let labels: Option<Vec<String>> = match obj.get("labels") {
                        Some(Value::Array(arr)) => Some(
                            arr.iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect(),
                        ),
                        _ => None,
                    };
                    let mut g = store.inner.write().unwrap();
                    let num = match g.create_issue(repo_id, title, issue_body, labels.as_deref()) {
                        Ok(n) => n,
                        Err((st, msg)) => {
                            write_json_message(write_buf, st, &msg);
                            return RestResponse::Written;
                        }
                    };
                    let issue = &g.repos.get(&repo_id).unwrap().issues[&num];
                    body_scratch.clear();
                    write_issue_json_into(body_scratch, issue);
                    write_http_json(write_buf, 201, b"", body_scratch);
                    return RestResponse::Written;
                }
            }
        }
    }

    if method == "GET" && (sub.is_empty() || sub == "/") {
        return RestResponse::Static(api_root_http());
    }

    if method == "GET" && sub == "/meta" {
        return RestResponse::Static(api_meta_http());
    }

    if method == "GET" && sub == "/user" {
        let mut json_body = Vec::with_capacity(192);
        let mut ibuf = itoa::Buffer::new();
        json_body.extend_from_slice(b"{\"id\":");
        json_body.extend_from_slice(ibuf.format(VIEWER_ID).as_bytes());
        json_body.extend_from_slice(b",\"node_id\":");
        json_escape_into(&mut json_body, VIEWER_NODE_ID);
        json_body.extend_from_slice(b",\"login\":");
        json_escape_into(&mut json_body, VIEWER_LOGIN);
        json_body.extend_from_slice(b",\"name\":");
        json_escape_into(&mut json_body, VIEWER_NAME);
        json_body.extend_from_slice(b",\"email\":");
        json_escape_into(&mut json_body, VIEWER_EMAIL);
        json_body.extend_from_slice(b",\"type\":\"User\"}");
        write_http_json(write_buf, 200, b"", &json_body);
        return RestResponse::Written;
    }

    if sub == "/user/repos" {
        if method == "GET" {
            let per_page = parse_pos_usize_query(query, "per_page", 30).min(100);
            let page = parse_pos_usize_query(query, "page", 1);
            let start = (page - 1) * per_page;

            let g = store.inner.read().unwrap();
            let total = g.viewer_repo_order.len();
            let mut json_body = Vec::with_capacity(512);
            json_body.push(b'[');
            let end = (start + per_page).min(total);
            if start < total {
                for (i, &rid) in g.viewer_repo_order[start..end].iter().enumerate() {
                    if i > 0 {
                        json_body.push(b',');
                    }
                    if let Some(repo) = g.repos.get(&rid) {
                        write_repo_json_into(&mut json_body, repo);
                    }
                }
            }
            json_body.push(b']');
            let extra = if end < total {
                let host = host_header.filter(|h| !h.is_empty()).unwrap_or("127.0.0.1");
                format!(
                    "Link: <http://{host}/api/v3/user/repos?per_page={per_page}&page={}>; rel=\"next\"\r\n",
                    page + 1
                )
            } else {
                String::new()
            };
            write_http_json(write_buf, 200, extra.as_bytes(), &json_body);
            return RestResponse::Written;
        }
        if method == "POST" {
            let Ok(obj) = parse_json_object(body) else {
                write_json_message(write_buf, 400, "Problems parsing JSON");
                return RestResponse::Written;
            };
            let Some(Value::String(name)) = obj.get("name") else {
                write_json_message(write_buf, 422, "Validation Failed: name is required");
                return RestResponse::Written;
            };
            if name.trim().is_empty() {
                write_json_message(write_buf, 422, "Validation Failed: name is required");
                return RestResponse::Written;
            }
            let desc = match obj.get("description") {
                Some(Value::String(d)) => d.as_str(),
                _ => "",
            };
            let is_private = match obj.get("private") {
                Some(Value::Bool(b)) => *b,
                _ => false,
            };
            let mut g = store.inner.write().unwrap();
            let rid = match g.create_repo(VIEWER_LOGIN, name, desc, is_private) {
                Ok(id) => id,
                Err((st, msg)) => {
                    write_json_message(write_buf, st, &msg);
                    return RestResponse::Written;
                }
            };
            let repo = g.repos.get(&rid).unwrap();
            let mut json_body = Vec::with_capacity(256);
            write_repo_json_into(&mut json_body, repo);
            write_http_json(write_buf, 201, b"", &json_body);
            return RestResponse::Written;
        }
    }

    let Some(repo_tail) = sub.strip_prefix("/repos/") else {
        return RestResponse::Static(not_found_http());
    };
    let Some(slash1) = repo_tail.find('/') else {
        return RestResponse::Static(not_found_http());
    };
    if slash1 == 0 {
        return RestResponse::Static(not_found_http());
    }
    let owner = cow_percent_decode(&repo_tail[..slash1]);
    let (repo_name, resource) = match repo_tail[slash1 + 1..].find('/') {
        None => (cow_percent_decode(&repo_tail[slash1 + 1..]), ""),
        Some(s2_rel) => {
            let s2 = slash1 + 1 + s2_rel;
            (cow_percent_decode(&repo_tail[slash1 + 1..s2]), &repo_tail[s2..])
        }
    };

    let repo_id = {
        let g = store.inner.read().unwrap();
        match g.find_repo_id(&owner, &repo_name) {
            Some(id) => id,
            None => return RestResponse::Static(not_found_http()),
        }
    };

    if resource.is_empty() {
        if method == "GET" {
            let g = store.inner.read().unwrap();
            let Some(repo) = g.repos.get(&repo_id) else {
                return RestResponse::Static(not_found_http());
            };
            let mut json_body = Vec::with_capacity(256);
            write_repo_json_into(&mut json_body, repo);
            write_http_json(write_buf, 200, b"", &json_body);
            return RestResponse::Written;
        }
        if method == "PATCH" {
            let Ok(obj) = parse_json_object(body) else {
                write_json_message(write_buf, 400, "Problems parsing JSON");
                return RestResponse::Written;
            };
            let mut g = store.inner.write().unwrap();
            let (_seq, iso, _) = g.next_stamp();
            let Some(repo) = g.repos.get_mut(&repo_id) else {
                return RestResponse::Static(not_found_http());
            };
            if let Some(Value::String(d)) = obj.get("description") {
                repo.description = d.clone();
            }
            if let Some(Value::Bool(p)) = obj.get("private") {
                repo.private = *p;
            }
            repo.updated_at = iso;
            let mut json_body = Vec::with_capacity(256);
            write_repo_json_into(&mut json_body, repo);
            store.bump_read_epoch();
            write_http_json(write_buf, 200, b"", &json_body);
            return RestResponse::Written;
        }
        if method == "DELETE" {
            let mut g = store.inner.write().unwrap();
            g.delete_repo(&owner, &repo_name);
            store.bump_read_epoch();
            store.bump_git_epoch();
            return RestResponse::Static(EMPTY_204_HTTP);
        }
    }

    if method == "GET" && resource == "/branches" {
        let g = store.inner.read().unwrap();
        let Some(repo) = g.repos.get(&repo_id) else {
            return RestResponse::Static(not_found_http());
        };
        let mut json_body = Vec::with_capacity(256);
        json_body.push(b'[');
        let mut first = true;
        for (ref_name, oid) in &repo.refs {
            if let Some(branch) = ref_name.strip_prefix("refs/heads/") {
                if !first {
                    json_body.push(b',');
                }
                first = false;
                json_body.extend_from_slice(b"{\"name\":");
                json_escape_into(&mut json_body, branch);
                json_body.extend_from_slice(b",\"commit\":{\"sha\":");
                json_escape_into(&mut json_body, &oid_to_string(oid));
                json_body.extend_from_slice(b"},\"protected\":false}");
            }
        }
        json_body.push(b']');
        write_http_json(write_buf, 200, b"", &json_body);
        return RestResponse::Written;
    }

    if method == "GET" && resource.starts_with("/branches/") {
        let branch_name = percent_decode(&resource["/branches/".len()..]);
        let g = store.inner.read().unwrap();
        let Some(repo) = g.repos.get(&repo_id) else {
            return RestResponse::Static(not_found_http());
        };
        match repo.refs.get(&format!("refs/heads/{branch_name}")) {
            Some(oid) => {
                let mut json_body = Vec::with_capacity(128);
                json_body.extend_from_slice(b"{\"name\":");
                json_escape_into(&mut json_body, &branch_name);
                json_body.extend_from_slice(b",\"commit\":{\"sha\":");
                json_escape_into(&mut json_body, &oid_to_string(oid));
                json_body.extend_from_slice(b"},\"protected\":false}");
                write_http_json(write_buf, 200, b"", &json_body);
            }
            None => write_json_message(write_buf, 404, "Branch not found"),
        }
        return RestResponse::Written;
    }

    if method == "POST" && resource == "/git/refs" {
        let Ok(obj) = parse_json_object(body) else {
            write_json_message(write_buf, 400, "Problems parsing JSON");
            return RestResponse::Written;
        };
        let r_ref = obj.get("ref").and_then(|v| v.as_str()).unwrap_or("");
        let sha = obj.get("sha").and_then(|v| v.as_str()).unwrap_or("");
        let mut g = store.inner.write().unwrap();
        let Some(repo) = g.repos.get_mut(&repo_id) else {
            return RestResponse::Static(not_found_http());
        };
        let Some(oid) = hex_to_oid(sha.as_bytes()) else {
            write_json_message(write_buf, 422, "Reference update failed: invalid ref or unknown sha");
            return RestResponse::Written;
        };
        if !r_ref.starts_with("refs/") || !repo.objects.contains_key(&oid) || oid == ZERO_OID {
            write_json_message(write_buf, 422, "Reference update failed: invalid ref or unknown sha");
            return RestResponse::Written;
        }
        if repo.refs.contains_key(r_ref) {
            write_json_message(write_buf, 422, "Reference already exists");
            return RestResponse::Written;
        }
        repo.refs.insert(r_ref.to_string(), oid);
        repo.invalidate_git_caches();
        store.bump_git_epoch();
        let mut json_body = Vec::with_capacity(128);
        json_body.extend_from_slice(b"{\"ref\":");
        json_escape_into(&mut json_body, r_ref);
        json_body.extend_from_slice(b",\"object\":{\"type\":\"commit\",\"sha\":");
        json_escape_into(&mut json_body, &oid_to_string(&oid));
        json_body.extend_from_slice(b"}}");
        write_http_json(write_buf, 201, b"", &json_body);
        return RestResponse::Written;
    }

    if method == "GET" && resource.starts_with("/git/refs/") {
        let ref_name = format!("refs/{}", percent_decode(&resource["/git/refs/".len()..]));
        let g = store.inner.read().unwrap();
        let Some(repo) = g.repos.get(&repo_id) else {
            return RestResponse::Static(not_found_http());
        };
        match repo.refs.get(&ref_name) {
            Some(oid) => {
                let mut json_body = Vec::with_capacity(128);
                json_body.extend_from_slice(b"{\"ref\":");
                json_escape_into(&mut json_body, &ref_name);
                json_body.extend_from_slice(b",\"object\":{\"type\":\"commit\",\"sha\":");
                json_escape_into(&mut json_body, &oid_to_string(oid));
                json_body.extend_from_slice(b"}}");
                write_http_json(write_buf, 200, b"", &json_body);
            }
            None => return RestResponse::Static(not_found_http()),
        }
        return RestResponse::Written;
    }

    if method == "GET" && resource == "/commits" {
        let sha_param = query_param(query, "sha");
        let g = store.inner.read().unwrap();
        let Some(repo) = g.repos.get(&repo_id) else {
            return RestResponse::Static(not_found_http());
        };
        let json_body = list_repo_commits_json(repo, sha_param.as_deref());
        write_http_json(write_buf, 200, b"", &json_body);
        return RestResponse::Written;
    }

    if resource == "/contents" || resource.starts_with("/contents/") {
        let raw_rel = if resource.len() <= "/contents".len() {
            ""
        } else {
            &resource["/contents/".len()..]
        };
        let rel_path = raw_rel
            .split('/')
            .map(percent_decode)
            .collect::<Vec<_>>()
            .join("/");

        if method == "GET" {
            let ref_param = query_param(query, "ref");
            let g = store.inner.read().unwrap();
            let got = match g.read_contents(repo_id, &rel_path, ref_param.as_deref()) {
                Some(res) => res,
                None => return RestResponse::Static(not_found_http()),
            };
            let mut json_body = Vec::with_capacity(512);
            match got {
                ReadContentsResult::Dir(entries) => {
                    let mut ibuf = itoa::Buffer::new();
                    json_body.push(b'[');
                    for (i, e) in entries.iter().enumerate() {
                        if i > 0 {
                            json_body.push(b',');
                        }
                        json_body.extend_from_slice(b"{\"type\":\"");
                        json_body.extend_from_slice(e.kind.as_bytes());
                        json_body.extend_from_slice(b"\",\"name\":");
                        json_escape_into(&mut json_body, &e.name);
                        json_body.extend_from_slice(b",\"path\":");
                        json_escape_into(&mut json_body, &e.path);
                        json_body.extend_from_slice(b",\"sha\":");
                        json_escape_into(&mut json_body, &e.sha);
                        json_body.extend_from_slice(b",\"size\":");
                        json_body.extend_from_slice(ibuf.format(e.size).as_bytes());
                        json_body.push(b'}');
                    }
                    json_body.push(b']');
                }
                ReadContentsResult::File {
                    name,
                    path,
                    sha,
                    size,
                    content_base64,
                } => {
                    let mut ibuf = itoa::Buffer::new();
                    json_body.extend_from_slice(b"{\"type\":\"file\",\"encoding\":\"base64\",\"name\":");
                    json_escape_into(&mut json_body, &name);
                    json_body.extend_from_slice(b",\"path\":");
                    json_escape_into(&mut json_body, &path);
                    json_body.extend_from_slice(b",\"sha\":");
                    json_escape_into(&mut json_body, &sha);
                    json_body.extend_from_slice(b",\"size\":");
                    json_body.extend_from_slice(ibuf.format(size).as_bytes());
                    json_body.extend_from_slice(b",\"content\":");
                    json_escape_into(&mut json_body, &content_base64);
                    json_body.push(b'}');
                }
            }
            write_http_json(write_buf, 200, b"", &json_body);
            return RestResponse::Written;
        }

        if method == "PUT" {
            let Ok(obj) = parse_json_object(body) else {
                write_json_message(write_buf, 400, "Problems parsing JSON");
                return RestResponse::Written;
            };
            let Some(Value::String(content)) = obj.get("content") else {
                write_json_message(write_buf, 422, "Validation Failed: content and message are required");
                return RestResponse::Written;
            };
            let Some(Value::String(message)) = obj.get("message") else {
                write_json_message(write_buf, 422, "Validation Failed: content and message are required");
                return RestResponse::Written;
            };
            let branch = obj.get("branch").and_then(|v| v.as_str());
            let sha = obj.get("sha").and_then(|v| v.as_str());

            let mut g = store.inner.write().unwrap();
            match g.put_content_file(repo_id, &rel_path, content, message, branch, sha) {
                Err((st, msg)) => write_json_message(write_buf, st, &msg),
                Ok((created, content_sha, commit_sha, size)) => {
                    store.bump_git_epoch();
                    let clean_path = rel_path.trim_matches('/');
                    let fname = clean_path.rsplit('/').next().unwrap_or(clean_path);
                    let mut json_body = Vec::with_capacity(256 + content.len());
                    let mut ibuf = itoa::Buffer::new();
                    json_body.extend_from_slice(b"{\"content\":{\"name\":");
                    json_escape_into(&mut json_body, fname);
                    json_body.extend_from_slice(b",\"path\":");
                    json_escape_into(&mut json_body, clean_path);
                    json_body.extend_from_slice(b",\"sha\":");
                    json_escape_into(&mut json_body, &content_sha);
                    json_body.extend_from_slice(b",\"size\":");
                    json_body.extend_from_slice(ibuf.format(size).as_bytes());
                    json_body.extend_from_slice(b",\"type\":\"file\",\"encoding\":\"base64\",\"content\":");
                    json_escape_into(&mut json_body, content);
                    json_body.extend_from_slice(b"},\"commit\":{\"sha\":");
                    json_escape_into(&mut json_body, &commit_sha);
                    json_body.extend_from_slice(b",\"message\":");
                    json_escape_into(&mut json_body, message);
                    json_body.extend_from_slice(b"}}");
                    write_http_json(write_buf, if created { 201 } else { 200 }, b"", &json_body);
                }
            }
            return RestResponse::Written;
        }

        if method == "DELETE" {
            let Ok(obj) = parse_json_object(body) else {
                write_json_message(write_buf, 400, "Problems parsing JSON");
                return RestResponse::Written;
            };
            let sha = obj.get("sha").and_then(|v| v.as_str()).unwrap_or("");
            let message = obj
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("Delete file");
            let branch = obj.get("branch").and_then(|v| v.as_str());
            let mut g = store.inner.write().unwrap();
            match g.delete_content_file(repo_id, &rel_path, message, sha, branch) {
                Err((st, msg)) => write_json_message(write_buf, st, &msg),
                Ok(commit_sha) => {
                    store.bump_git_epoch();
                    let mut json_body = Vec::with_capacity(96);
                    json_body.extend_from_slice(b"{\"content\":null,\"commit\":{\"sha\":");
                    json_escape_into(&mut json_body, &commit_sha);
                    json_body.extend_from_slice(b"}}");
                    write_http_json(write_buf, 200, b"", &json_body);
                }
            }
            return RestResponse::Written;
        }
    }

    if resource == "/labels" {
        if method == "GET" {
            let g = store.inner.read().unwrap();
            let Some(repo) = g.repos.get(&repo_id) else {
                return RestResponse::Static(not_found_http());
            };
            let mut json_body = Vec::with_capacity(256);
            json_body.push(b'[');
            for (i, lname) in repo.label_order.iter().enumerate() {
                if i > 0 {
                    json_body.push(b',');
                }
                if let Some(lbl) = repo.labels.get(lname) {
                    write_label_json_into(&mut json_body, lbl);
                }
            }
            json_body.push(b']');
            write_http_json(write_buf, 200, b"", &json_body);
            return RestResponse::Written;
        }
        if method == "POST" {
            let Ok(obj) = parse_json_object(body) else {
                write_json_message(write_buf, 400, "Problems parsing JSON");
                return RestResponse::Written;
            };
            let Some(Value::String(name)) = obj.get("name") else {
                write_json_message(write_buf, 422, "Validation Failed: label name is required");
                return RestResponse::Written;
            };
            if name.trim().is_empty() {
                write_json_message(write_buf, 422, "Validation Failed: label name is required");
                return RestResponse::Written;
            }
            let color = obj.get("color").and_then(|v| v.as_str()).unwrap_or("ededed");
            let desc = obj.get("description").and_then(|v| v.as_str()).unwrap_or("");
            let mut g = store.inner.write().unwrap();
            let lbl = g.create_label(repo_id, name, color, desc);
            let mut json_body = Vec::with_capacity(128);
            write_label_json_into(&mut json_body, &lbl);
            write_http_json(write_buf, 201, b"", &json_body);
            return RestResponse::Written;
        }
    }

    if method == "GET" && resource == "/issues" {
        let state_filter = query_param(query, "state").unwrap_or_else(|| "open".to_string());
        let direction = query_param(query, "direction").unwrap_or_else(|| "desc".to_string());
        let per_page = parse_pos_usize_query(query, "per_page", 30).min(100);
        let page = parse_pos_usize_query(query, "page", 1);

        let g = store.inner.read().unwrap();
        let Some(repo) = g.repos.get(&repo_id) else {
            return RestResponse::Static(not_found_http());
        };
        let mut items: Vec<&Issue> = repo
            .issue_order
            .iter()
            .filter_map(|n| repo.issues.get(n))
            .filter(|i| state_filter == "all" || i.state_str() == state_filter)
            .collect();
        if direction == "asc" {
            items.sort_by(|a, b| a.created_seq.cmp(&b.created_seq).then(a.number.cmp(&b.number)));
        } else {
            items.sort_by(|a, b| b.created_seq.cmp(&a.created_seq).then(b.number.cmp(&a.number)));
        }
        let start = (page - 1) * per_page;
        let mut json_body = Vec::with_capacity(512);
        json_body.push(b'[');
        if start < items.len() {
            let end = (start + per_page).min(items.len());
            for (i, issue) in items[start..end].iter().enumerate() {
                if i > 0 {
                    json_body.push(b',');
                }
                write_issue_json_into(&mut json_body, issue);
            }
        }
        json_body.push(b']');
        write_http_json(write_buf, 200, b"", &json_body);
        return RestResponse::Written;
    }

    if let Some(tail) = resource.strip_prefix("/issues/") {
        let (num_str, sub_res) = match tail.find('/') {
            Some(idx) => (&tail[..idx], &tail[idx..]),
            None => (tail, ""),
        };
        let Some(num) = parse_ascii_uint(num_str) else {
            return RestResponse::Static(not_found_http());
        };

        if sub_res.is_empty() && method == "PATCH" {
            let Ok(obj) = parse_json_object(body) else {
                write_json_message(write_buf, 400, "Problems parsing JSON");
                return RestResponse::Written;
            };
            let title = obj.get("title").and_then(|v| v.as_str());
            let issue_body = obj.get("body").and_then(|v| v.as_str());
            let state = match obj.get("state") {
                None => None,
                Some(Value::String(s)) if s == "open" => Some(true),
                Some(Value::String(s)) if s == "closed" => Some(false),
                _ => {
                    write_json_message(write_buf, 422, "Validation Failed: invalid state");
                    return RestResponse::Written;
                }
            };
            let mut g = store.inner.write().unwrap();
            if !g.update_issue(repo_id, num, title, issue_body, state) {
                return RestResponse::Static(not_found_http());
            }
            store.bump_read_epoch();
            let issue = g.repos.get_mut(&repo_id).unwrap().issues.get_mut(&num).unwrap();
            let (_, http_cache) = issue.ensure_json_and_http();
            return RestResponse::Cached(http_cache);
        }

        if sub_res == "/comments" {
            if method == "GET" {
                let g = store.inner.read().unwrap();
                let Some(issue) = g.repos.get(&repo_id).and_then(|r| r.issues.get(&num)) else {
                    return RestResponse::Static(not_found_http());
                };
                let mut json_body = Vec::with_capacity(256);
                json_body.push(b'[');
                for (i, c) in issue.comments.iter().enumerate() {
                    if i > 0 {
                        json_body.push(b',');
                    }
                    write_comment_json_into(&mut json_body, c);
                }
                json_body.push(b']');
                write_http_json(write_buf, 200, b"", &json_body);
                return RestResponse::Written;
            }
            if method == "POST" {
                let Ok(obj) = parse_json_object(body) else {
                    write_json_message(write_buf, 400, "Problems parsing JSON");
                    return RestResponse::Written;
                };
                let Some(Value::String(comment_body)) = obj.get("body") else {
                    write_json_message(write_buf, 422, "Validation Failed: comment body is required");
                    return RestResponse::Written;
                };
                let mut g = store.inner.write().unwrap();
                let Some(comment) = g.add_comment(repo_id, num, comment_body) else {
                    return RestResponse::Static(not_found_http());
                };
                store.bump_read_epoch();
                let mut json_body = Vec::with_capacity(192);
                write_comment_json_into(&mut json_body, &comment);
                write_http_json(write_buf, 201, b"", &json_body);
                return RestResponse::Written;
            }
        }
    }

    if resource == "/pulls" {
        if method == "GET" {
            let state_filter = query_param(query, "state").unwrap_or_else(|| "open".to_string());
            let per_page = parse_pos_usize_query(query, "per_page", 30).min(100);
            let page = parse_pos_usize_query(query, "page", 1);

            let g = store.inner.read().unwrap();
            let Some(repo) = g.repos.get(&repo_id) else {
                return RestResponse::Static(not_found_http());
            };
            let mut items: Vec<&Pull> = repo
                .pull_order
                .iter()
                .filter_map(|n| repo.pulls.get(n))
                .filter(|p| {
                    state_filter == "all"
                        || (p.is_open && state_filter == "open")
                        || (!p.is_open && state_filter == "closed")
                })
                .collect();
            items.sort_by(|a, b| b.created_seq.cmp(&a.created_seq));
            let start = (page - 1) * per_page;
            let mut json_body = Vec::with_capacity(512);
            json_body.push(b'[');
            if start < items.len() {
                let end = (start + per_page).min(items.len());
                for (i, pr) in items[start..end].iter().enumerate() {
                    if i > 0 {
                        json_body.push(b',');
                    }
                    write_pull_json_into(&mut json_body, repo, pr);
                }
            }
            json_body.push(b']');
            write_http_json(write_buf, 200, b"", &json_body);
            return RestResponse::Written;
        }
        if method == "POST" {
            let Ok(obj) = parse_json_object(body) else {
                write_json_message(write_buf, 400, "Problems parsing JSON");
                return RestResponse::Written;
            };
            let (Some(Value::String(title)), Some(Value::String(head)), Some(Value::String(base))) =
                (obj.get("title"), obj.get("head"), obj.get("base"))
            else {
                write_json_message(write_buf, 422, "Validation Failed: title, head, and base are required");
                return RestResponse::Written;
            };
            let pr_body = obj.get("body").and_then(|v| v.as_str()).unwrap_or("");
            let mut g = store.inner.write().unwrap();
            let num = match g.create_pull(repo_id, title, pr_body, head, base) {
                Ok(n) => n,
                Err((st, msg)) => {
                    write_json_message(write_buf, st, &msg);
                    return RestResponse::Written;
                }
            };
            let repo = g.repos.get(&repo_id).unwrap();
            let pr = &repo.pulls[&num];
            let mut json_body = Vec::with_capacity(384);
            write_pull_json_into(&mut json_body, repo, pr);
            write_http_json(write_buf, 201, b"", &json_body);
            return RestResponse::Written;
        }
    }

    if let Some(tail) = resource.strip_prefix("/pulls/") {
        let (num_str, sub_res) = match tail.find('/') {
            Some(idx) => (&tail[..idx], &tail[idx..]),
            None => (tail, ""),
        };
        let Some(num) = parse_ascii_uint(num_str) else {
            return RestResponse::Static(not_found_http());
        };

        if sub_res.is_empty() && method == "GET" {
            let g = store.inner.read().unwrap();
            let Some(repo) = g.repos.get(&repo_id) else {
                return RestResponse::Static(not_found_http());
            };
            let Some(pr) = repo.pulls.get(&num) else {
                return RestResponse::Static(not_found_http());
            };
            let mut json_body = Vec::with_capacity(384);
            write_pull_json_into(&mut json_body, repo, pr);
            write_http_json(write_buf, 200, b"", &json_body);
            return RestResponse::Written;
        }

        if sub_res == "/files" && method == "GET" {
            let g = store.inner.read().unwrap();
            let Some(repo) = g.repos.get(&repo_id) else {
                return RestResponse::Static(not_found_http());
            };
            let Some(pr) = repo.pulls.get(&num) else {
                return RestResponse::Static(not_found_http());
            };
            let files: Vec<PullFileChange> = repo.compute_changed_files(&pr.base_sha, &pr.head_sha);
            let mut json_body = Vec::with_capacity(files.len() * 96 + 8);
            let mut ibuf = itoa::Buffer::new();
            json_body.push(b'[');
            for (i, f) in files.iter().enumerate() {
                if i > 0 {
                    json_body.push(b',');
                }
                json_body.extend_from_slice(b"{\"filename\":");
                json_escape_into(&mut json_body, &f.filename);
                json_body.extend_from_slice(b",\"status\":\"");
                json_body.extend_from_slice(f.status.as_bytes());
                json_body.extend_from_slice(b"\",\"additions\":");
                json_body.extend_from_slice(ibuf.format(f.additions).as_bytes());
                json_body.extend_from_slice(b",\"deletions\":");
                json_body.extend_from_slice(ibuf.format(f.deletions).as_bytes());
                json_body.extend_from_slice(b",\"changes\":");
                json_body.extend_from_slice(ibuf.format(f.changes).as_bytes());
                json_body.push(b'}');
            }
            json_body.push(b']');
            write_http_json(write_buf, 200, b"", &json_body);
            return RestResponse::Written;
        }

        if sub_res == "/merge" && method == "PUT" {
            let Ok(obj) = parse_json_object(body) else {
                write_json_message(write_buf, 400, "Problems parsing JSON");
                return RestResponse::Written;
            };
            let commit_title = obj.get("commit_title").and_then(|v| v.as_str());
            let mut g = store.inner.write().unwrap();
            match g.merge_pull(repo_id, num, commit_title) {
                Err((st, msg)) => write_json_message(write_buf, st, &msg),
                Ok(sha) => {
                    store.bump_git_epoch();
                    let mut json_body = Vec::with_capacity(128);
                    json_body.extend_from_slice(b"{\"sha\":");
                    json_escape_into(&mut json_body, &oid_to_string(&sha));
                    json_body.extend_from_slice(
                        b",\"merged\":true,\"message\":\"Pull Request successfully merged\"}",
                    );
                    write_http_json(write_buf, 200, b"", &json_body);
                }
            }
            return RestResponse::Written;
        }
    }

    let _ = (BTreeMap::<String, ()>::new(),);
    RestResponse::Static(not_found_http())
}
