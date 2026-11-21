use std::sync::OnceLock;

use rustc_hash::{FxHashMap, FxHashSet};
use serde_json::{json, Map, Value};

use crate::rest::{write_http_json, write_json_message, write_pull_json_into};
use crate::store::{
    base64_decode_lenient, base64url_encode, write_issue_json_into, ForgeStore, NodeTarget,
    StoreInner, VIEWER_LOGIN, VIEWER_NAME, VIEWER_NODE_ID,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum TokKind {
    Name,
    Int,
    Float,
    Str,
    Punct,
    Eof,
}

#[derive(Clone)]
struct Token {
    kind: TokKind,
    val: String,
}

#[derive(Clone)]
enum SelKind {
    Field,
    InlineFragment,
    FragmentSpread,
}

#[derive(Clone)]
struct Selection {
    kind: SelKind,
    name: String,
    alias: Option<String>,
    type_cond: Option<String>,
    args: Option<Map<String, Value>>,
    sels: Option<Vec<Selection>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OpType {
    Query,
    Mutation,
}

struct Operation {
    op_type: OpType,
    name: Option<String>,
    defaults: Map<String, Value>,
    sels: Vec<Selection>,
}

struct Fragment {
    type_cond: String,
    sels: Vec<Selection>,
}

struct Document {
    ops: Vec<Operation>,
    fragments: FxHashMap<String, Fragment>,
}

fn known_fields_map() -> &'static FxHashMap<&'static str, FxHashSet<&'static str>> {
    static MAP: OnceLock<FxHashMap<&'static str, FxHashSet<&'static str>>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut m = FxHashMap::default();
        let entries: &[(&str, &[&str])] = &[
            ("Query", &["viewer", "repository", "node", "__type", "__typename"]),
            (
                "Mutation",
                &[
                    "createIssue",
                    "closeIssue",
                    "createPullRequest",
                    "mergePullRequest",
                    "addComment",
                    "__typename",
                ],
            ),
            ("User", &["login", "id", "name", "__typename"]),
            (
                "Repository",
                &[
                    "id",
                    "databaseId",
                    "name",
                    "nameWithOwner",
                    "owner",
                    "defaultBranchRef",
                    "viewerPermission",
                    "hasIssuesEnabled",
                    "isPrivate",
                    "description",
                    "issue",
                    "issues",
                    "pullRequests",
                    "pullRequest",
                    "__typename",
                ],
            ),
            ("Ref", &["name", "prefix", "__typename"]),
            (
                "Issue",
                &[
                    "id",
                    "number",
                    "title",
                    "state",
                    "body",
                    "createdAt",
                    "updatedAt",
                    "closedAt",
                    "__typename",
                ],
            ),
            (
                "PullRequest",
                &[
                    "id",
                    "number",
                    "title",
                    "body",
                    "headRefName",
                    "baseRefName",
                    "mergeable",
                    "state",
                    "merged",
                    "mergedAt",
                    "files",
                    "__typename",
                ],
            ),
            (
                "IssueConnection",
                &["nodes", "edges", "pageInfo", "totalCount", "__typename"],
            ),
            (
                "PullRequestConnection",
                &["nodes", "edges", "pageInfo", "totalCount", "__typename"],
            ),
            (
                "PullRequestFileConnection",
                &["nodes", "pageInfo", "totalCount", "__typename"],
            ),
            (
                "PullRequestFile",
                &["path", "additions", "deletions", "changeType", "__typename"],
            ),
            (
                "PageInfo",
                &[
                    "hasNextPage",
                    "hasPreviousPage",
                    "startCursor",
                    "endCursor",
                    "__typename",
                ],
            ),
            ("CreateIssuePayload", &["issue", "clientMutationId", "__typename"]),
            ("CloseIssuePayload", &["issue", "clientMutationId", "__typename"]),
            (
                "CreatePullRequestPayload",
                &["pullRequest", "clientMutationId", "__typename"],
            ),
            (
                "MergePullRequestPayload",
                &["pullRequest", "clientMutationId", "__typename"],
            ),
            ("AddCommentPayload", &["commentEdge", "clientMutationId", "__typename"]),
            ("CommentEdge", &["node", "__typename"]),
            ("Comment", &["id", "body", "createdAt", "__typename"]),
            ("__Type", &["name", "kind", "fields", "enumValues", "__typename"]),
            ("__Field", &["name", "isDeprecated", "__typename"]),
            ("__EnumValue", &["name", "isDeprecated", "__typename"]),
        ];
        for (k, fs) in entries {
            let mut set = FxHashSet::default();
            for &f in *fs {
                set.insert(f);
            }
            m.insert(*k, set);
        }
        m
    })
}

fn tokenize(src: &str) -> Result<Vec<Token>, String> {
    let b = src.as_bytes();
    let n = b.len();
    let mut i = 0usize;
    let mut toks = Vec::with_capacity(64);
    while i < n {
        let ch = b[i];
        if ch == b' ' || ch == b'\t' || ch == b'\n' || ch == b'\r' || ch == b',' {
            i += 1;
            continue;
        }
        if ch == b'#' {
            while i < n && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if b[i..].starts_with(b"...") {
            toks.push(Token {
                kind: TokKind::Punct,
                val: "...".to_string(),
            });
            i += 3;
            continue;
        }
        if matches!(
            ch,
            b'{' | b'}' | b'(' | b')' | b'[' | b']' | b':' | b'=' | b'@' | b'$' | b'!'
        ) {
            toks.push(Token {
                kind: TokKind::Punct,
                val: (ch as char).to_string(),
            });
            i += 1;
            continue;
        }
        if ch == b'"' {
            i += 1;
            if b[i..].starts_with(b"\"\"") {
                i += 2;
                let end = src[i..].find("\"\"\"").map(|p| i + p);
                let val = match end {
                    Some(e) => {
                        let s = src[i..e].to_string();
                        i = e + 3;
                        s
                    }
                    None => {
                        let s = src[i..].to_string();
                        i = n;
                        s
                    }
                };
                toks.push(Token {
                    kind: TokKind::Str,
                    val,
                });
                continue;
            }
            let mut val = String::new();
            while i < n && b[i] != b'"' {
                if b[i] == b'\\' && i + 1 < n {
                    let esc = b[i + 1];
                    match esc {
                        b'n' => val.push('\n'),
                        b'r' => val.push('\r'),
                        b't' => val.push('\t'),
                        _ => val.push(esc as char),
                    }
                    i += 2;
                } else {
                    let ch_str = src[i..].chars().next().unwrap();
                    val.push(ch_str);
                    i += ch_str.len_utf8();
                }
            }
            if i < n {
                i += 1;
            }
            toks.push(Token {
                kind: TokKind::Str,
                val,
            });
            continue;
        }
        if ch.is_ascii_digit() || ch == b'-' {
            let start = i;
            i += 1;
            let mut is_float = false;
            while i < n
                && (b[i].is_ascii_digit()
                    || matches!(b[i], b'.' | b'e' | b'E' | b'+' | b'-'))
            {
                if matches!(b[i], b'.' | b'e' | b'E') {
                    is_float = true;
                }
                i += 1;
            }
            toks.push(Token {
                kind: if is_float { TokKind::Float } else { TokKind::Int },
                val: src[start..i].to_string(),
            });
            continue;
        }
        if ch.is_ascii_alphabetic() || ch == b'_' {
            let start = i;
            i += 1;
            while i < n && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
            }
            toks.push(Token {
                kind: TokKind::Name,
                val: src[start..i].to_string(),
            });
            continue;
        }
        return Err(format!("Unexpected GraphQL token character '{}'", ch as char));
    }
    toks.push(Token {
        kind: TokKind::Eof,
        val: String::new(),
    });
    Ok(toks)
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> &Token {
        self.tokens.get(self.pos).unwrap_or_else(|| self.tokens.last().unwrap())
    }

    fn next(&mut self) -> Token {
        let t = self.peek().clone();
        if t.kind != TokKind::Eof {
            self.pos += 1;
        }
        t
    }

    fn expect(&mut self, expected: &str) -> Result<(), String> {
        let t = self.next();
        if t.val != expected {
            return Err(format!("Expected '{expected}', got '{}'", t.val));
        }
        Ok(())
    }

    fn skip_type_ref(&mut self) -> Result<(), String> {
        if self.peek().val == "[" {
            self.next();
            self.skip_type_ref()?;
            self.expect("]")?;
        } else {
            self.next();
        }
        if self.peek().val == "!" {
            self.next();
        }
        Ok(())
    }

    fn parse_value(&mut self) -> Result<Value, String> {
        let t = self.peek().clone();
        if t.val == "$" {
            self.next();
            let vname = self.next().val;
            return Ok(json!({ "__gqlVar": vname }));
        }
        match t.kind {
            TokKind::Int => {
                self.next();
                let n = t
                    .val
                    .parse::<i64>()
                    .map_err(|_| format!("Invalid int '{}'", t.val))?;
                Ok(Value::from(n))
            }
            TokKind::Float => {
                self.next();
                let f = t
                    .val
                    .parse::<f64>()
                    .map_err(|_| format!("Invalid float '{}'", t.val))?;
                Ok(Value::from(f))
            }
            TokKind::Str => {
                self.next();
                Ok(Value::String(t.val))
            }
            TokKind::Name => {
                self.next();
                match t.val.as_str() {
                    "true" => Ok(Value::Bool(true)),
                    "false" => Ok(Value::Bool(false)),
                    "null" => Ok(Value::Null),
                    _ => Ok(Value::String(t.val)),
                }
            }
            _ if t.val == "[" => {
                self.next();
                let mut arr = Vec::new();
                while self.peek().val != "]" && self.peek().kind != TokKind::Eof {
                    arr.push(self.parse_value()?);
                }
                self.expect("]")?;
                Ok(Value::Array(arr))
            }
            _ if t.val == "{" => {
                self.next();
                let mut obj = Map::new();
                while self.peek().val != "}" && self.peek().kind != TokKind::Eof {
                    let key = self.next().val;
                    self.expect(":")?;
                    obj.insert(key, self.parse_value()?);
                }
                self.expect("}")?;
                Ok(Value::Object(obj))
            }
            _ => Err(format!("Unexpected value token '{}'", t.val)),
        }
    }

    fn parse_arguments(&mut self) -> Result<Map<String, Value>, String> {
        let mut args = Map::new();
        if self.peek().val != "(" {
            return Ok(args);
        }
        self.next();
        while self.peek().val != ")" && self.peek().kind != TokKind::Eof {
            let name = self.next().val;
            self.expect(":")?;
            args.insert(name, self.parse_value()?);
        }
        self.expect(")")?;
        Ok(args)
    }

    fn skip_directives(&mut self) -> Result<(), String> {
        while self.peek().val == "@" {
            self.next();
            self.next();
            if self.peek().val == "(" {
                self.parse_arguments()?;
            }
        }
        Ok(())
    }

    fn parse_selection_set(&mut self) -> Result<Vec<Selection>, String> {
        self.expect("{")?;
        let mut sels = Vec::new();
        while self.peek().val != "}" && self.peek().kind != TokKind::Eof {
            if self.peek().val == "..." {
                self.next();
                if self.peek().val == "on" {
                    self.next();
                    let type_cond = self.next().val;
                    self.skip_directives()?;
                    let sub = self.parse_selection_set()?;
                    sels.push(Selection {
                        kind: SelKind::InlineFragment,
                        name: type_cond.clone(),
                        alias: None,
                        type_cond: Some(type_cond),
                        args: None,
                        sels: Some(sub),
                    });
                } else if self.peek().val == "{" {
                    let sub = self.parse_selection_set()?;
                    sels.push(Selection {
                        kind: SelKind::InlineFragment,
                        name: String::new(),
                        alias: None,
                        type_cond: None,
                        args: None,
                        sels: Some(sub),
                    });
                } else {
                    let frag_name = self.next().val;
                    self.skip_directives()?;
                    sels.push(Selection {
                        kind: SelKind::FragmentSpread,
                        name: frag_name,
                        alias: None,
                        type_cond: None,
                        args: None,
                        sels: None,
                    });
                }
            } else {
                let first = self.next().val;
                let (alias, name) = if self.peek().val == ":" {
                    self.next();
                    (Some(first), self.next().val)
                } else {
                    (None, first)
                };
                let args = if self.peek().val == "(" {
                    Some(self.parse_arguments()?)
                } else {
                    None
                };
                self.skip_directives()?;
                let sub = if self.peek().val == "{" {
                    Some(self.parse_selection_set()?)
                } else {
                    None
                };
                sels.push(Selection {
                    kind: SelKind::Field,
                    name,
                    alias,
                    type_cond: None,
                    args,
                    sels: sub,
                });
            }
        }
        self.expect("}")?;
        Ok(sels)
    }

    fn parse_document(&mut self) -> Result<Document, String> {
        let mut ops = Vec::new();
        let mut fragments = FxHashMap::default();
        while self.peek().kind != TokKind::Eof {
            let t = self.peek().clone();
            if t.val == "{" {
                let sels = self.parse_selection_set()?;
                ops.push(Operation {
                    op_type: OpType::Query,
                    name: None,
                    defaults: Map::new(),
                    sels,
                });
                continue;
            }
            if t.val == "fragment" {
                self.next();
                let frag_name = self.next().val;
                self.expect("on")?;
                let type_cond = self.next().val;
                self.skip_directives()?;
                let sels = self.parse_selection_set()?;
                fragments.insert(frag_name, Fragment { type_cond, sels });
                continue;
            }
            if t.val == "query" || t.val == "mutation" {
                let op_type = if t.val == "mutation" {
                    OpType::Mutation
                } else {
                    OpType::Query
                };
                self.next();
                let name = if self.peek().kind == TokKind::Name {
                    Some(self.next().val)
                } else {
                    None
                };
                let mut defaults = Map::new();
                if self.peek().val == "(" {
                    self.next();
                    while self.peek().val != ")" && self.peek().kind != TokKind::Eof {
                        self.expect("$")?;
                        let vname = self.next().val;
                        self.expect(":")?;
                        self.skip_type_ref()?;
                        if self.peek().val == "=" {
                            self.next();
                            defaults.insert(vname, self.parse_value()?);
                        }
                        self.skip_directives()?;
                    }
                    self.expect(")")?;
                }
                self.skip_directives()?;
                let sels = self.parse_selection_set()?;
                ops.push(Operation {
                    op_type,
                    name,
                    defaults,
                    sels,
                });
                continue;
            }
            return Err(format!("Unexpected top-level token '{}'", t.val));
        }
        Ok(Document { ops, fragments })
    }
}

fn substitute_vars(val: &Value, vars: &Map<String, Value>) -> Value {
    match val {
        Value::Array(arr) => Value::Array(arr.iter().map(|x| substitute_vars(x, vars)).collect()),
        Value::Object(map) => {
            if let Some(Value::String(vname)) = map.get("__gqlVar") {
                return vars.get(vname).cloned().unwrap_or(Value::Null);
            }
            let mut out = Map::new();
            for (k, v) in map {
                out.insert(k.clone(), substitute_vars(v, vars));
            }
            Value::Object(out)
        }
        _ => val.clone(),
    }
}

fn encode_cursor(issue_number: u64) -> String {
    base64url_encode(format!("issue:{issue_number}").as_bytes())
}

fn decode_cursor(val: Option<&Value>) -> Option<u64> {
    let s = val.and_then(|v| v.as_str())?;
    if s.is_empty() {
        return None;
    }
    let bytes = base64_decode_lenient(s.as_bytes())?;
    let raw = std::str::from_utf8(&bytes).ok()?;
    let rest = raw.strip_prefix("issue:")?;
    let n = rest.parse::<u64>().ok()?;
    if n > 0 { Some(n) } else { None }
}

fn make_gql_error(msg: &str, path: &[Value]) -> Value {
    if path.is_empty() {
        json!({ "message": msg })
    } else {
        json!({ "message": msg, "path": path })
    }
}

fn flatten_selections(
    doc: &Document,
    sels: &[Selection],
    runtime_type: &str,
) -> Vec<Selection> {
    let mut out = Vec::new();
    for s in sels {
        match s.kind {
            SelKind::Field => out.push(s.clone()),
            SelKind::InlineFragment => {
                if s.type_cond.as_deref().map(|t| t == runtime_type).unwrap_or(true) {
                    if let Some(sub) = &s.sels {
                        out.extend(flatten_selections(doc, sub, runtime_type));
                    }
                }
            }
            SelKind::FragmentSpread => {
                if let Some(frag) = doc.fragments.get(&s.name) {
                    if frag.type_cond == runtime_type {
                        out.extend(flatten_selections(doc, &frag.sels, runtime_type));
                    }
                }
            }
        }
    }
    out
}

fn resolve_value(
    store_inner: &mut StoreInner,
    doc: &Document,
    vars: &Map<String, Value>,
    errors: &mut Vec<Value>,
    raw: Value,
    expected_type: Option<&str>,
    sels: Option<&[Selection]>,
    path: &[Value],
) -> Value {
    match raw {
        Value::Null => Value::Null,
        Value::Array(arr) => {
            let mut res = Vec::with_capacity(arr.len());
            for (idx, item) in arr.into_iter().enumerate() {
                let mut child_path = path.to_vec();
                child_path.push(Value::from(idx as u64));
                res.push(resolve_value(
                    store_inner,
                    doc,
                    vars,
                    errors,
                    item,
                    expected_type,
                    sels,
                    &child_path,
                ));
            }
            Value::Array(res)
        }
        Value::Object(map) => {
            if let Some(sub_sels) = sels {
                let type_name = map
                    .get("__type")
                    .and_then(|v| v.as_str())
                    .or(expected_type)
                    .unwrap_or("Unknown")
                    .to_string();
                resolve_selection_set(store_inner, doc, vars, errors, &map, &type_name, sub_sels, path)
            } else {
                Value::Object(map)
            }
        }
        other => other,
    }
}

fn resolve_selection_set(
    store_inner: &mut StoreInner,
    doc: &Document,
    vars: &Map<String, Value>,
    errors: &mut Vec<Value>,
    obj: &Map<String, Value>,
    type_name: &str,
    sels: &[Selection],
    path: &[Value],
) -> Value {
    let mut out = Map::new();
    let flat = flatten_selections(doc, sels, type_name);
    let known = known_fields_map().get(type_name);

    for sel in flat {
        let out_key = sel.alias.clone().unwrap_or_else(|| sel.name.clone());
        if sel.name == "__typename" {
            out.insert(out_key, Value::String(type_name.to_string()));
            continue;
        }
        if let Some(allowed) = known {
            if !allowed.contains(sel.name.as_str()) {
                let mut err_path = path.to_vec();
                err_path.push(Value::String(out_key));
                errors.push(make_gql_error(
                    &format!("Field '{}' doesn't exist on type '{type_name}'", sel.name),
                    &err_path,
                ));
                continue;
            }
        }
        let args = match &sel.args {
            Some(a) => match substitute_vars(&Value::Object(a.clone()), vars) {
                Value::Object(m) => m,
                _ => Map::new(),
            },
            None => Map::new(),
        };
        let mut child_path = path.to_vec();
        child_path.push(Value::String(out_key.clone()));
        let val = resolve_field(
            store_inner,
            doc,
            vars,
            errors,
            obj,
            type_name,
            &sel.name,
            &args,
            sel.sels.as_deref(),
            &child_path,
        );
        out.insert(out_key, val);
    }
    Value::Object(out)
}

fn introspection_spec(name: &str) -> Option<(&'static str, &'static [&'static str], &'static [&'static str])> {
    match name {
        "Issue" => Some((
            "OBJECT",
            &[
                "id",
                "number",
                "title",
                "state",
                "body",
                "createdAt",
                "updatedAt",
                "closedAt",
            ],
            &[],
        )),
        "PullRequest" => Some((
            "OBJECT",
            &[
                "id",
                "number",
                "title",
                "body",
                "headRefName",
                "baseRefName",
                "mergeable",
                "state",
                "merged",
                "files",
            ],
            &[],
        )),
        "Repository" => Some((
            "OBJECT",
            &[
                "id",
                "databaseId",
                "name",
                "nameWithOwner",
                "owner",
                "defaultBranchRef",
                "viewerPermission",
                "hasIssuesEnabled",
                "issue",
                "issues",
                "pullRequests",
                "pullRequest",
            ],
            &[],
        )),
        "SearchType" => Some(("ENUM", &[], &["ISSUE", "REPOSITORY", "USER", "DISCUSSION"])),
        _ => None,
    }
}

fn repo_marker(repo_id: u64) -> Value {
    json!({ "__type": "Repository", "__repoId": repo_id })
}

fn issue_marker(repo_id: u64, number: u64) -> Value {
    json!({ "__type": "Issue", "__repoId": repo_id, "__number": number })
}

fn pull_marker(repo_id: u64, number: u64) -> Value {
    json!({ "__type": "PullRequest", "__repoId": repo_id, "__number": number })
}

fn comment_marker(repo_id: u64, issue_number: u64, idx: usize) -> Value {
    json!({ "__type": "Comment", "__repoId": repo_id, "__issueNumber": issue_number, "__idx": idx as u64 })
}

fn resolve_field(
    store: &mut StoreInner,
    doc: &Document,
    vars: &Map<String, Value>,
    errors: &mut Vec<Value>,
    parent: &Map<String, Value>,
    type_name: &str,
    field_name: &str,
    args: &Map<String, Value>,
    sels: Option<&[Selection]>,
    path: &[Value],
) -> Value {
    match type_name {
        "Query" => match field_name {
            "viewer" => {
                let raw = json!({
                    "__type": "User",
                    "login": VIEWER_LOGIN,
                    "id": VIEWER_NODE_ID,
                    "name": VIEWER_NAME
                });
                return resolve_value(store, doc, vars, errors, raw, Some("User"), sels, path);
            }
            "repository" => {
                let owner = args.get("owner").and_then(|v| v.as_str()).unwrap_or("");
                let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let rid = store.find_repo_id(owner, name);
                return match rid {
                    Some(id) => resolve_value(
                        store,
                        doc,
                        vars,
                        errors,
                        repo_marker(id),
                        Some("Repository"),
                        sels,
                        path,
                    ),
                    None => Value::Null,
                };
            }
            "node" => {
                let id = args.get("id").and_then(|v| v.as_str()).unwrap_or("");
                let Some(target) = store.nodes_by_id.get(id).cloned() else {
                    return Value::Null;
                };
                return match target {
                    NodeTarget::Repository(rid) => resolve_value(
                        store,
                        doc,
                        vars,
                        errors,
                        repo_marker(rid),
                        Some("Repository"),
                        sels,
                        path,
                    ),
                    NodeTarget::Issue(rid, num) => resolve_value(
                        store,
                        doc,
                        vars,
                        errors,
                        issue_marker(rid, num),
                        Some("Issue"),
                        sels,
                        path,
                    ),
                    NodeTarget::PullRequest(rid, num) => resolve_value(
                        store,
                        doc,
                        vars,
                        errors,
                        pull_marker(rid, num),
                        Some("PullRequest"),
                        sels,
                        path,
                    ),
                    NodeTarget::IssueComment(rid, inum, idx) => resolve_value(
                        store,
                        doc,
                        vars,
                        errors,
                        comment_marker(rid, inum, idx),
                        Some("Comment"),
                        sels,
                        path,
                    ),
                };
            }
            "__type" => {
                let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let Some((kind, fields, enum_vals)) = introspection_spec(name) else {
                    return Value::Null;
                };
                let fs: Vec<Value> = fields
                    .iter()
                    .map(|f| json!({ "__type": "__Field", "name": f, "isDeprecated": false }))
                    .collect();
                let evs: Vec<Value> = enum_vals
                    .iter()
                    .map(|e| json!({ "__type": "__EnumValue", "name": e, "isDeprecated": false }))
                    .collect();
                let raw = json!({
                    "__type": "__Type",
                    "name": name,
                    "kind": kind,
                    "fields": fs,
                    "enumValues": evs
                });
                return resolve_value(store, doc, vars, errors, raw, Some("__Type"), sels, path);
            }
            _ => {}
        },
        "Mutation" => {
            let empty_map = Map::new();
            let input = args
                .get("input")
                .and_then(|v| v.as_object())
                .unwrap_or(&empty_map);
            let client_mut_id = input.get("clientMutationId").cloned().unwrap_or(Value::Null);

            match field_name {
                "createIssue" => {
                    let repo_id_str = input.get("repositoryId").and_then(|v| v.as_str()).unwrap_or("");
                    let Some(NodeTarget::Repository(rid)) = store.nodes_by_id.get(repo_id_str).cloned() else {
                        errors.push(make_gql_error("Repository not found", path));
                        return Value::Null;
                    };
                    let title = input.get("title").and_then(|v| v.as_str()).unwrap_or("");
                    let body = input.get("body").and_then(|v| v.as_str()).unwrap_or("");
                    match store.create_issue(rid, title, body, None) {
                        Ok(num) => {
                            let raw = json!({
                                "__type": "CreateIssuePayload",
                                "issue": issue_marker(rid, num),
                                "clientMutationId": client_mut_id
                            });
                            return resolve_value(
                                store,
                                doc,
                                vars,
                                errors,
                                raw,
                                Some("CreateIssuePayload"),
                                sels,
                                path,
                            );
                        }
                        Err((_, msg)) => {
                            errors.push(make_gql_error(&msg, path));
                            return Value::Null;
                        }
                    }
                }
                "closeIssue" => {
                    let issue_id_str = input.get("issueId").and_then(|v| v.as_str()).unwrap_or("");
                    let Some(NodeTarget::Issue(rid, num)) = store.nodes_by_id.get(issue_id_str).cloned() else {
                        errors.push(make_gql_error("Issue not found", path));
                        return Value::Null;
                    };
                    store.update_issue(rid, num, None, None, Some(false));
                    let raw = json!({
                        "__type": "CloseIssuePayload",
                        "issue": issue_marker(rid, num),
                        "clientMutationId": client_mut_id
                    });
                    return resolve_value(
                        store,
                        doc,
                        vars,
                        errors,
                        raw,
                        Some("CloseIssuePayload"),
                        sels,
                        path,
                    );
                }
                "createPullRequest" => {
                    let repo_id_str = input.get("repositoryId").and_then(|v| v.as_str()).unwrap_or("");
                    let Some(NodeTarget::Repository(rid)) = store.nodes_by_id.get(repo_id_str).cloned() else {
                        errors.push(make_gql_error("Repository not found", path));
                        return Value::Null;
                    };
                    let title = input.get("title").and_then(|v| v.as_str()).unwrap_or("");
                    let body = input.get("body").and_then(|v| v.as_str()).unwrap_or("");
                    let head = input.get("headRefName").and_then(|v| v.as_str()).unwrap_or("");
                    let base = input.get("baseRefName").and_then(|v| v.as_str()).unwrap_or("");
                    match store.create_pull(rid, title, body, head, base) {
                        Ok(num) => {
                            let raw = json!({
                                "__type": "CreatePullRequestPayload",
                                "pullRequest": pull_marker(rid, num),
                                "clientMutationId": client_mut_id
                            });
                            return resolve_value(
                                store,
                                doc,
                                vars,
                                errors,
                                raw,
                                Some("CreatePullRequestPayload"),
                                sels,
                                path,
                            );
                        }
                        Err((_, msg)) => {
                            errors.push(make_gql_error(&msg, path));
                            return Value::Null;
                        }
                    }
                }
                "mergePullRequest" => {
                    let pr_id_str = input.get("pullRequestId").and_then(|v| v.as_str()).unwrap_or("");
                    let Some(NodeTarget::PullRequest(rid, num)) = store.nodes_by_id.get(pr_id_str).cloned() else {
                        errors.push(make_gql_error("Pull request not found", path));
                        return Value::Null;
                    };
                    match store.merge_pull(rid, num, None) {
                        Ok(_) => {
                            let raw = json!({
                                "__type": "MergePullRequestPayload",
                                "pullRequest": pull_marker(rid, num),
                                "clientMutationId": client_mut_id
                            });
                            return resolve_value(
                                store,
                                doc,
                                vars,
                                errors,
                                raw,
                                Some("MergePullRequestPayload"),
                                sels,
                                path,
                            );
                        }
                        Err((_, msg)) => {
                            errors.push(make_gql_error(&msg, path));
                            return Value::Null;
                        }
                    }
                }
                "addComment" => {
                    let subj = input.get("subjectId").and_then(|v| v.as_str()).unwrap_or("");
                    let Some(NodeTarget::Issue(rid, inum)) = store.nodes_by_id.get(subj).cloned() else {
                        errors.push(make_gql_error("Subject not found", path));
                        return Value::Null;
                    };
                    let body = input.get("body").and_then(|v| v.as_str()).unwrap_or("");
                    let idx_opt = store.add_comment(rid, inum, body).map(|_| {
                        store.repos.get(&rid).unwrap().issues[&inum].comments.len() - 1
                    });
                    if let Some(idx) = idx_opt {
                        let raw = json!({
                            "__type": "AddCommentPayload",
                            "commentEdge": {
                                "__type": "CommentEdge",
                                "node": comment_marker(rid, inum, idx)
                            },
                            "clientMutationId": client_mut_id
                        });
                        return resolve_value(
                            store,
                            doc,
                            vars,
                            errors,
                            raw,
                            Some("AddCommentPayload"),
                            sels,
                            path,
                        );
                    }
                    errors.push(make_gql_error("Subject not found", path));
                    return Value::Null;
                }
                _ => {}
            }
        }
        "Repository" => {
            let rid = parent.get("__repoId").and_then(|v| v.as_u64()).unwrap_or(0);
            let Some(repo) = store.repos.get(&rid) else {
                return Value::Null;
            };
            match field_name {
                "id" => return Value::String(repo.node_id.clone()),
                "databaseId" => return Value::from(repo.id),
                "name" => return Value::String(repo.name.clone()),
                "nameWithOwner" => return Value::String(format!("{}/{}", repo.owner, repo.name)),
                "owner" => {
                    let raw = json!({ "__type": "User", "login": repo.owner, "id": VIEWER_NODE_ID });
                    return resolve_value(store, doc, vars, errors, raw, Some("User"), sels, path);
                }
                "defaultBranchRef" => {
                    let exists = repo.refs.contains_key(&repo.head_ref_name());
                    if !exists {
                        return Value::Null;
                    }
                    let raw = json!({ "__type": "Ref", "name": repo.default_branch, "prefix": "refs/heads/" });
                    return resolve_value(store, doc, vars, errors, raw, Some("Ref"), sels, path);
                }
                "viewerPermission" => return Value::String("ADMIN".to_string()),
                "hasIssuesEnabled" => return Value::Bool(true),
                "isPrivate" => return Value::Bool(repo.private),
                "description" => return Value::String(repo.description.clone()),
                "issue" => {
                    let num = args.get("number").and_then(|v| v.as_u64()).unwrap_or(0);
                    return if repo.issues.contains_key(&num) {
                        resolve_value(store, doc, vars, errors, issue_marker(rid, num), Some("Issue"), sels, path)
                    } else {
                        Value::Null
                    };
                }
                "issues" => {
                    let states: Option<FxHashSet<String>> = args.get("states").and_then(|v| v.as_array()).map(|arr| {
                        arr.iter()
                            .filter_map(|x| x.as_str().map(|s| s.to_ascii_lowercase()))
                            .collect()
                    });
                    let direction = args
                        .get("orderBy")
                        .and_then(|v| v.as_object())
                        .and_then(|m| m.get("direction"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_ascii_uppercase())
                        .unwrap_or_else(|| "ASC".to_string());

                    let mut items: Vec<(u64, u64)> = repo
                        .issue_order
                        .iter()
                        .filter_map(|n| repo.issues.get(n))
                        .filter(|i| {
                            states
                                .as_ref()
                                .map(|st| st.contains(i.state_str()))
                                .unwrap_or(true)
                        })
                        .map(|i| (i.created_seq, i.number))
                        .collect();
                    if direction == "DESC" {
                        items.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)));
                    } else {
                        items.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
                    }

                    let total = items.len();
                    let start_idx = match decode_cursor(args.get("after")) {
                        Some(after_num) => items
                            .iter()
                            .position(|&(_, n)| n == after_num)
                            .map(|p| p + 1)
                            .unwrap_or(0),
                        None => 0,
                    };
                    let first = args
                        .get("first")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(30) as usize;
                    let end_idx = (start_idx + first).min(total);
                    let slice = &items[start_idx..end_idx];
                    let has_next = end_idx < total;
                    let start_cursor = slice.first().map(|&(_, n)| Value::String(encode_cursor(n))).unwrap_or(Value::Null);
                    let end_cursor = slice.last().map(|&(_, n)| Value::String(encode_cursor(n))).unwrap_or(Value::Null);

                    let nodes: Vec<Value> = slice.iter().map(|&(_, n)| issue_marker(rid, n)).collect();
                    let edges: Vec<Value> = slice
                        .iter()
                        .map(|&(_, n)| json!({ "node": issue_marker(rid, n), "cursor": encode_cursor(n) }))
                        .collect();
                    let raw = json!({
                        "__type": "IssueConnection",
                        "nodes": nodes,
                        "edges": edges,
                        "totalCount": total,
                        "pageInfo": {
                            "__type": "PageInfo",
                            "hasNextPage": has_next,
                            "hasPreviousPage": start_idx > 0,
                            "startCursor": start_cursor,
                            "endCursor": end_cursor
                        }
                    });
                    return resolve_value(
                        store,
                        doc,
                        vars,
                        errors,
                        raw,
                        Some("IssueConnection"),
                        sels,
                        path,
                    );
                }
                "pullRequests" => {
                    let states: Option<FxHashSet<String>> = args.get("states").and_then(|v| v.as_array()).map(|arr| {
                        arr.iter()
                            .filter_map(|x| x.as_str().map(|s| s.to_ascii_uppercase()))
                            .collect()
                    });
                    let mut items: Vec<(u64, u64)> = repo
                        .pull_order
                        .iter()
                        .filter_map(|n| repo.pulls.get(n))
                        .filter(|pr| {
                            if let Some(st) = &states {
                                let gstate = if pr.merged {
                                    "MERGED"
                                } else if pr.is_open {
                                    "OPEN"
                                } else {
                                    "CLOSED"
                                };
                                st.contains(gstate)
                            } else {
                                true
                            }
                        })
                        .map(|pr| (pr.created_seq, pr.number))
                        .collect();
                    items.sort_by(|a, b| b.0.cmp(&a.0));
                    let total = items.len();
                    let first = args
                        .get("first")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(30) as usize;
                    let slice = &items[..first.min(total)];
                    let nodes: Vec<Value> = slice.iter().map(|&(_, n)| pull_marker(rid, n)).collect();
                    let raw = json!({
                        "__type": "PullRequestConnection",
                        "nodes": nodes,
                        "totalCount": total,
                        "pageInfo": {
                            "__type": "PageInfo",
                            "hasNextPage": slice.len() < total,
                            "endCursor": null
                        }
                    });
                    return resolve_value(
                        store,
                        doc,
                        vars,
                        errors,
                        raw,
                        Some("PullRequestConnection"),
                        sels,
                        path,
                    );
                }
                "pullRequest" => {
                    let num = args.get("number").and_then(|v| v.as_u64()).unwrap_or(0);
                    return if repo.pulls.contains_key(&num) {
                        resolve_value(
                            store,
                            doc,
                            vars,
                            errors,
                            pull_marker(rid, num),
                            Some("PullRequest"),
                            sels,
                            path,
                        )
                    } else {
                        Value::Null
                    };
                }
                _ => {}
            }
        }
        "Issue" => {
            let rid = parent.get("__repoId").and_then(|v| v.as_u64()).unwrap_or(0);
            let num = parent.get("__number").and_then(|v| v.as_u64()).unwrap_or(0);
            let Some(issue) = store.repos.get(&rid).and_then(|r| r.issues.get(&num)) else {
                return Value::Null;
            };
            match field_name {
                "id" => return Value::String(issue.node_id.clone()),
                "number" => return Value::from(issue.number),
                "title" => return Value::String(issue.title.clone()),
                "body" => return Value::String(issue.body.clone()),
                "state" => return Value::String(issue.state_str().to_ascii_uppercase()),
                "createdAt" => return Value::String(issue.created_at.clone()),
                "updatedAt" => return Value::String(issue.updated_at.clone()),
                "closedAt" => {
                    return match &issue.closed_at {
                        Some(ts) => Value::String(ts.clone()),
                        None => Value::Null,
                    }
                }
                _ => {}
            }
        }
        "PullRequest" => {
            let rid = parent.get("__repoId").and_then(|v| v.as_u64()).unwrap_or(0);
            let num = parent.get("__number").and_then(|v| v.as_u64()).unwrap_or(0);
            let Some(repo) = store.repos.get(&rid) else {
                return Value::Null;
            };
            let Some(pr) = repo.pulls.get(&num) else {
                return Value::Null;
            };
            match field_name {
                "id" => return Value::String(pr.node_id.clone()),
                "number" => return Value::from(pr.number),
                "title" => return Value::String(pr.title.clone()),
                "body" => return Value::String(pr.body.clone()),
                "headRefName" => return Value::String(pr.head_ref.clone()),
                "baseRefName" => return Value::String(pr.base_ref.clone()),
                "state" => {
                    return Value::String(
                        if pr.merged {
                            "MERGED"
                        } else if pr.is_open {
                            "OPEN"
                        } else {
                            "CLOSED"
                        }
                        .to_string(),
                    );
                }
                "merged" => return Value::Bool(pr.merged),
                "mergedAt" => {
                    return match &pr.merged_at {
                        Some(ts) => Value::String(ts.clone()),
                        None => Value::Null,
                    }
                }
                "mergeable" => return Value::String(repo.is_pull_mergeable(pr).to_string()),
                "files" => {
                    let first = args.get("first").and_then(|v| v.as_u64()).unwrap_or(30) as usize;
                    let changed = repo.compute_changed_files(&pr.base_sha, &pr.head_sha);
                    let total = changed.len();
                    let nodes: Vec<Value> = changed
                        .into_iter()
                        .take(first)
                        .map(|c| {
                            json!({
                                "__type": "PullRequestFile",
                                "path": c.filename,
                                "additions": c.additions,
                                "deletions": c.deletions,
                                "changeType": c.status.to_ascii_uppercase()
                            })
                        })
                        .collect();
                    let raw = json!({
                        "__type": "PullRequestFileConnection",
                        "nodes": nodes,
                        "totalCount": total
                    });
                    return resolve_value(
                        store,
                        doc,
                        vars,
                        errors,
                        raw,
                        Some("PullRequestFileConnection"),
                        sels,
                        path,
                    );
                }
                _ => {}
            }
        }
        "Comment" => {
            let rid = parent.get("__repoId").and_then(|v| v.as_u64()).unwrap_or(0);
            let inum = parent.get("__issueNumber").and_then(|v| v.as_u64()).unwrap_or(0);
            let idx = parent.get("__idx").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let Some(c) = store
                .repos
                .get(&rid)
                .and_then(|r| r.issues.get(&inum))
                .and_then(|i| i.comments.get(idx))
            else {
                return Value::Null;
            };
            match field_name {
                "id" => return Value::String(c.node_id.clone()),
                "body" => return Value::String(c.body.clone()),
                "createdAt" => return Value::String(c.created_at.clone()),
                _ => {}
            }
        }
        _ => {}
    }

    if let Some(v) = parent.get(field_name) {
        return resolve_value(store, doc, vars, errors, v.clone(), None, sels, path);
    }
    Value::Null
}

fn execute_one_op(store: &ForgeStore, item: &Value) -> Value {
    let Some(rec) = item.as_object() else {
        return json!({
            "data": null,
            "errors": [{ "message": "Invalid GraphQL operation body" }]
        });
    };
    let query_str = rec.get("query").and_then(|v| v.as_str()).unwrap_or("");
    let vars = rec
        .get("variables")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let op_name = rec.get("operationName").and_then(|v| v.as_str());

    let toks = match tokenize(query_str) {
        Ok(t) => t,
        Err(e) => return json!({ "data": null, "errors": [{ "message": e }] }),
    };
    let doc = match Parser::new(toks).parse_document() {
        Ok(d) => d,
        Err(e) => return json!({ "data": null, "errors": [{ "message": e }] }),
    };
    let op = match op_name {
        Some(n) => doc.ops.iter().find(|o| o.name.as_deref() == Some(n)).or_else(|| doc.ops.first()),
        None => doc.ops.first(),
    };
    let Some(op) = op else {
        return json!({ "data": null, "errors": [{ "message": "No operation found in GraphQL document" }] });
    };

    let mut resolved_vars = op.defaults.clone();
    for (k, v) in vars {
        resolved_vars.insert(k, v);
    }
    let mut errors = Vec::new();
    let root_type = if op.op_type == OpType::Mutation {
        "Mutation"
    } else {
        "Query"
    };
    let empty_parent = Map::new();

    let mut guard = store.inner.write().unwrap();
    let data = resolve_selection_set(
        &mut guard,
        &doc,
        &resolved_vars,
        &mut errors,
        &empty_parent,
        root_type,
        &op.sels,
        &[],
    );
    if op.op_type == OpType::Mutation {
        store.bump_read_epoch();
        store.bump_git_epoch();
    }
    drop(guard);

    if errors.is_empty() {
        json!({ "data": data })
    } else {
        json!({ "data": data, "errors": errors })
    }
}

pub fn handle_graphql(store: &ForgeStore, method: &str, body: &[u8], write_buf: &mut Vec<u8>) {
    if method != "POST" {
        write_json_message(write_buf, 405, "Method Not Allowed");
        return;
    }
    let Ok(parsed) = serde_json::from_slice::<Value>(body) else {
        write_json_message(write_buf, 400, "Problems parsing JSON");
        return;
    };
    let resp_val = match parsed {
        Value::Array(items) => Value::Array(items.iter().map(|it| execute_one_op(store, it)).collect()),
        single => execute_one_op(store, &single),
    };
    let json_bytes = serde_json::to_vec(&resp_val).unwrap_or_else(|_| b"{}".to_vec());
    write_http_json(write_buf, 200, b"", &json_bytes);
}

#[allow(dead_code)]
fn _keep_imports() {
    let _ = (write_issue_json_into, write_pull_json_into);
}
