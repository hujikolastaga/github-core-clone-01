use std::sync::OnceLock;

use serde_json::{json, Map, Value};

use crate::rest::{
    write_http_json, write_json_message, write_pull_json_into, write_repo_json_into,
};
use crate::sha1::oid_to_string;
use crate::store::{write_issue_json_into, ForgeStore, Issue, VIEWER_LOGIN};

static TOOLS_RESULT_SUFFIX: OnceLock<Vec<u8>> = OnceLock::new();
static DELETE_204_HTTP: &[u8] = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nX-GitHub-Request-Id: 1\r\n\r\n";
static NOTIF_202_HTTP: &[u8] = b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nX-GitHub-Request-Id: 1\r\n\r\n";

fn tools_result_suffix() -> &'static [u8] {
    TOOLS_RESULT_SUFFIX.get_or_init(|| {
        let tools_val = json!({
            "tools": [
                {
                    "name": "create_repo",
                    "description": "Create a new Git repository under the authenticated user account.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "owner": { "type": "string", "description": "Repository owner login" },
                            "name": { "type": "string", "description": "Repository name" },
                            "description": { "type": "string", "description": "Repository description" },
                            "private": { "type": "boolean", "description": "Whether the repository is private" }
                        },
                        "required": ["name"]
                    }
                },
                {
                    "name": "get_repo",
                    "description": "Fetch metadata for an existing Git repository.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "owner": { "type": "string", "description": "Repository owner login" },
                            "repo": { "type": "string", "description": "Repository name" }
                        },
                        "required": ["owner", "repo"]
                    }
                },
                {
                    "name": "create_issue",
                    "description": "Create a new issue in a repository.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "owner": { "type": "string", "description": "Repository owner login" },
                            "repo": { "type": "string", "description": "Repository name" },
                            "title": { "type": "string", "description": "Issue title" },
                            "body": { "type": "string", "description": "Issue body text" },
                            "labels": { "type": "array", "items": { "type": "string" }, "description": "Issue label names" }
                        },
                        "required": ["owner", "repo", "title"]
                    }
                },
                {
                    "name": "list_issues",
                    "description": "List issues in a repository filtered by state.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "owner": { "type": "string", "description": "Repository owner login" },
                            "repo": { "type": "string", "description": "Repository name" },
                            "state": { "type": "string", "enum": ["open", "closed", "all"], "description": "Issue state filter" }
                        },
                        "required": ["owner", "repo"]
                    }
                },
                {
                    "name": "create_pull_request",
                    "description": "Create a new pull request from a head branch to a base branch.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "owner": { "type": "string", "description": "Repository owner login" },
                            "repo": { "type": "string", "description": "Repository name" },
                            "title": { "type": "string", "description": "Pull request title" },
                            "head": { "type": "string", "description": "Source branch name" },
                            "base": { "type": "string", "description": "Target branch name" },
                            "body": { "type": "string", "description": "Pull request body text" }
                        },
                        "required": ["owner", "repo", "title", "head", "base"]
                    }
                },
                {
                    "name": "merge_pull_request",
                    "description": "Merge an open pull request into its base branch.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "owner": { "type": "string", "description": "Repository owner login" },
                            "repo": { "type": "string", "description": "Repository name" },
                            "pull_number": { "type": "number", "description": "Pull request number" },
                            "commit_title": { "type": "string", "description": "Optional merge commit title" }
                        },
                        "required": ["owner", "repo", "pull_number"]
                    }
                }
            ]
        });
        let s = format!(",\"result\":{}}}", serde_json::to_string(&tools_val).unwrap());
        s.into_bytes()
    })
}

fn send_rpc_error(write_buf: &mut Vec<u8>, http_status: u16, id: &Value, code: i32, msg: &str) {
    let body = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": msg }
    }))
    .unwrap();
    write_http_json(write_buf, http_status, b"", &body);
}

fn send_tool_ok(write_buf: &mut Vec<u8>, id: &Value, payload: Value) {
    let text = serde_json::to_string(&payload).unwrap();
    let structured = match &payload {
        Value::Object(_) => payload,
        Value::Array(arr) => json!({ "items": payload, "count": arr.len() }),
        _ => json!({ "value": payload }),
    };
    let body = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "content": [{ "type": "text", "text": text }],
            "structuredContent": structured
        }
    }))
    .unwrap();
    write_http_json(write_buf, 200, b"", &body);
}

fn send_tool_err(write_buf: &mut Vec<u8>, id: &Value, msg: &str) {
    let text = serde_json::to_string(&json!({ "message": msg })).unwrap();
    let body = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "content": [{ "type": "text", "text": text }],
            "isError": true
        }
    }))
    .unwrap();
    write_http_json(write_buf, 200, b"", &body);
}

fn non_empty_str<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    map.get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
}

fn parse_pos_u64_arg(val: Option<&Value>) -> Option<u64> {
    match val? {
        Value::Number(n) => n.as_u64().filter(|&x| x > 0).or_else(|| {
            n.as_f64().and_then(|f| {
                if f > 0.0 && f.fract() == 0.0 && f <= (u64::MAX as f64) {
                    Some(f as u64)
                } else {
                    None
                }
            })
        }),
        Value::String(s) => s.trim().parse::<u64>().ok().filter(|&x| x > 0),
        _ => None,
    }
}

fn json_val_from_writer<F: FnOnce(&mut Vec<u8>)>(f: F) -> Value {
    let mut tmp = Vec::with_capacity(256);
    f(&mut tmp);
    serde_json::from_slice(&tmp).unwrap_or(Value::Null)
}

fn invoke_tool(
    store: &ForgeStore,
    id: &Value,
    name: &str,
    args: &Map<String, Value>,
    write_buf: &mut Vec<u8>,
) {
    match name {
        "create_repo" => {
            let Some(rname) = non_empty_str(args, "name") else {
                send_rpc_error(write_buf, 200, id, -32602, "Invalid params: name is required");
                return;
            };
            let owner = non_empty_str(args, "owner").unwrap_or(VIEWER_LOGIN);
            if owner != VIEWER_LOGIN {
                send_tool_err(write_buf, id, "Cannot create repository for another owner");
                return;
            }
            let desc = args.get("description").and_then(|v| v.as_str()).unwrap_or("");
            let is_private = args.get("private").and_then(|v| v.as_bool()).unwrap_or(false);
            let mut g = store.inner.write().unwrap();
            let rid = match g.create_repo(owner, rname, desc, is_private) {
                Ok(i) => i,
                Err((_, msg)) => {
                    send_tool_err(write_buf, id, &msg);
                    return;
                }
            };
            let val = json_val_from_writer(|b| write_repo_json_into(b, g.repos.get(&rid).unwrap()));
            drop(g);
            send_tool_ok(write_buf, id, val);
        }
        "get_repo" => {
            let Some(owner) = non_empty_str(args, "owner") else {
                send_rpc_error(write_buf, 200, id, -32602, "Invalid params: owner and repo are required");
                return;
            };
            let Some(rname) = non_empty_str(args, "repo").or_else(|| non_empty_str(args, "name")) else {
                send_rpc_error(write_buf, 200, id, -32602, "Invalid params: owner and repo are required");
                return;
            };
            let g = store.inner.read().unwrap();
            let Some(repo) = g.get_repo(owner, rname) else {
                send_tool_err(write_buf, id, "Not Found");
                return;
            };
            let val = json_val_from_writer(|b| write_repo_json_into(b, repo));
            drop(g);
            send_tool_ok(write_buf, id, val);
        }
        "create_issue" => {
            let (Some(owner), Some(rname), Some(title)) = (
                non_empty_str(args, "owner"),
                non_empty_str(args, "repo").or_else(|| non_empty_str(args, "name")),
                non_empty_str(args, "title"),
            ) else {
                send_rpc_error(
                    write_buf,
                    200,
                    id,
                    -32602,
                    "Invalid params: owner, repo, and title are required",
                );
                return;
            };
            let body_txt = args.get("body").and_then(|v| v.as_str()).unwrap_or("");
            let labels: Option<Vec<String>> = args.get("labels").and_then(|v| v.as_array()).map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                    .collect()
            });
            let mut g = store.inner.write().unwrap();
            let Some(rid) = g.find_repo_id(owner, rname) else {
                send_tool_err(write_buf, id, "Not Found");
                return;
            };
            let num = match g.create_issue(rid, title, body_txt, labels.as_deref()) {
                Ok(n) => n,
                Err((_, msg)) => {
                    send_tool_err(write_buf, id, &msg);
                    return;
                }
            };
            let issue = &g.repos.get(&rid).unwrap().issues[&num];
            let val = json_val_from_writer(|b| write_issue_json_into(b, issue));
            drop(g);
            send_tool_ok(write_buf, id, val);
        }
        "list_issues" => {
            let (Some(owner), Some(rname)) = (
                non_empty_str(args, "owner"),
                non_empty_str(args, "repo").or_else(|| non_empty_str(args, "name")),
            ) else {
                send_rpc_error(write_buf, 200, id, -32602, "Invalid params: owner and repo are required");
                return;
            };
            let state_filter = args.get("state").and_then(|v| v.as_str()).unwrap_or("open");
            if !matches!(state_filter, "open" | "closed" | "all") {
                send_rpc_error(write_buf, 200, id, -32602, "Invalid params: state must be open, closed, or all");
                return;
            }
            let g = store.inner.read().unwrap();
            let Some(repo) = g.get_repo(owner, rname) else {
                send_tool_err(write_buf, id, "Not Found");
                return;
            };
            let mut items: Vec<&Issue> = repo
                .issue_order
                .iter()
                .filter_map(|n| repo.issues.get(n))
                .filter(|i| state_filter == "all" || i.state_str() == state_filter)
                .collect();
            items.sort_by(|a, b| b.created_seq.cmp(&a.created_seq).then(b.number.cmp(&a.number)));
            let vals: Vec<Value> = items
                .into_iter()
                .map(|i| json_val_from_writer(|b| write_issue_json_into(b, i)))
                .collect();
            drop(g);
            send_tool_ok(write_buf, id, Value::Array(vals));
        }
        "create_pull_request" => {
            let (Some(owner), Some(rname), Some(title), Some(head), Some(base)) = (
                non_empty_str(args, "owner"),
                non_empty_str(args, "repo").or_else(|| non_empty_str(args, "name")),
                non_empty_str(args, "title"),
                non_empty_str(args, "head"),
                non_empty_str(args, "base"),
            ) else {
                send_rpc_error(
                    write_buf,
                    200,
                    id,
                    -32602,
                    "Invalid params: owner, repo, title, head, and base are required",
                );
                return;
            };
            let body_txt = args.get("body").and_then(|v| v.as_str()).unwrap_or("");
            let mut g = store.inner.write().unwrap();
            let Some(rid) = g.find_repo_id(owner, rname) else {
                send_tool_err(write_buf, id, "Not Found");
                return;
            };
            let num = match g.create_pull(rid, title, body_txt, head, base) {
                Ok(n) => n,
                Err((_, msg)) => {
                    send_tool_err(write_buf, id, &msg);
                    return;
                }
            };
            let repo = g.repos.get(&rid).unwrap();
            let pr = &repo.pulls[&num];
            let val = json_val_from_writer(|b| write_pull_json_into(b, repo, pr));
            drop(g);
            send_tool_ok(write_buf, id, val);
        }
        "merge_pull_request" => {
            let (Some(owner), Some(rname), Some(pull_number)) = (
                non_empty_str(args, "owner"),
                non_empty_str(args, "repo").or_else(|| non_empty_str(args, "name")),
                parse_pos_u64_arg(args.get("pull_number")),
            ) else {
                send_rpc_error(
                    write_buf,
                    200,
                    id,
                    -32602,
                    "Invalid params: owner, repo, and positive integer pull_number are required",
                );
                return;
            };
            let commit_title = args.get("commit_title").and_then(|v| v.as_str());
            let mut g = store.inner.write().unwrap();
            let Some(rid) = g.find_repo_id(owner, rname) else {
                send_tool_err(write_buf, id, "Not Found");
                return;
            };
            let sha = match g.merge_pull(rid, pull_number, commit_title) {
                Ok(s) => s,
                Err((_, msg)) => {
                    send_tool_err(write_buf, id, &msg);
                    return;
                }
            };
            store.bump_git_epoch();
            drop(g);
            send_tool_ok(
                write_buf,
                id,
                json!({
                    "sha": oid_to_string(&sha),
                    "merged": true,
                    "message": "Pull Request successfully merged",
                    "pull_number": pull_number
                }),
            );
        }
        _ => send_rpc_error(write_buf, 200, id, -32601, &format!("Unknown tool: {name}")),
    }
}

pub fn handle_mcp(store: &ForgeStore, method: &str, body: &[u8], write_buf: &mut Vec<u8>) {
    if method == "DELETE" {
        write_buf.extend_from_slice(DELETE_204_HTTP);
        return;
    }
    if method != "POST" {
        write_json_message(write_buf, 405, "Method Not Allowed");
        return;
    }
    let Ok(parsed) = serde_json::from_slice::<Value>(body) else {
        send_rpc_error(write_buf, 400, &Value::Null, -32700, "Parse error");
        return;
    };
    let Value::Object(msg) = parsed else {
        send_rpc_error(write_buf, 400, &Value::Null, -32600, "Invalid Request");
        return;
    };
    let has_id = msg.contains_key("id");
    let rpc_id = msg.get("id").cloned().unwrap_or(Value::Null);
    let Some(rpc_method) = msg.get("method").and_then(|v| v.as_str()) else {
        send_rpc_error(write_buf, 400, &rpc_id, -32600, "Invalid Request: method must be a string");
        return;
    };

    if !has_id && rpc_method.starts_with("notifications/") {
        write_buf.extend_from_slice(NOTIF_202_HTTP);
        return;
    }

    match rpc_method {
        "server/discover" => {
            let body_bytes = serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {
                    "supportedVersions": ["2026-07-28", "2025-11-25"],
                    "serverInfo": { "name": "makefun-forge", "version": "1.0.0" },
                    "capabilities": { "tools": {} },
                    "_meta": {
                        "io.modelcontextprotocol/serverInfo": {
                            "name": "makefun-forge",
                            "version": "1.0.0"
                        }
                    }
                }
            }))
            .unwrap();
            write_http_json(write_buf, 200, b"", &body_bytes);
        }
        "initialize" => {
            let body_bytes = serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "makefun-forge", "version": "1.0.0" }
                }
            }))
            .unwrap();
            write_http_json(write_buf, 200, b"", &body_bytes);
        }
        "ping" => {
            let body_bytes = serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {}
            }))
            .unwrap();
            write_http_json(write_buf, 200, b"", &body_bytes);
        }
        "tools/list" => {
            let id_json = serde_json::to_string(&rpc_id).unwrap();
            let suffix = tools_result_suffix();
            let mut body_bytes = Vec::with_capacity(24 + id_json.len() + suffix.len());
            body_bytes.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"id\":");
            body_bytes.extend_from_slice(id_json.as_bytes());
            body_bytes.extend_from_slice(suffix);
            write_http_json(write_buf, 200, b"", &body_bytes);
        }
        "tools/call" => {
            let Some(params) = msg.get("params").and_then(|v| v.as_object()) else {
                send_rpc_error(write_buf, 200, &rpc_id, -32602, "Invalid params");
                return;
            };
            let Some(tool_name) = params.get("name").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) else {
                send_rpc_error(write_buf, 200, &rpc_id, -32602, "Invalid params: tool name is required");
                return;
            };
            let empty_args = Map::new();
            let args = match params.get("arguments") {
                None => &empty_args,
                Some(Value::Object(m)) => m,
                _ => {
                    send_rpc_error(
                        write_buf,
                        200,
                        &rpc_id,
                        -32602,
                        "Invalid params: arguments must be an object",
                    );
                    return;
                }
            };
            invoke_tool(store, &rpc_id, tool_name, args, write_buf);
        }
        _ => send_rpc_error(
            write_buf,
            200,
            &rpc_id,
            -32601,
            &format!("Method not found: {rpc_method}"),
        ),
    }
}
