mod git_http;
mod graphql;
mod http;
mod mcp;
mod pack;
mod rest;
mod sha1;
mod store;

use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process;
use std::thread;
use std::time::Duration;

use http::AppContext;

struct ParsedUrl {
    host_port: String,
    host_header: String,
    base_path: String,
}

fn parse_http_url(raw: &str) -> Result<ParsedUrl, String> {
    let rest = raw
        .strip_prefix("http://")
        .ok_or_else(|| format!("Unsupported MAKEFUN_ENV_URL scheme: {raw}"))?;
    let trimmed = rest.trim_end_matches('/');
    let (authority, base_path) = match trimmed.find('/') {
        Some(idx) => (&trimmed[..idx], trimmed[idx..].to_string()),
        None => (trimmed, String::new()),
    };
    let host_port = if authority.contains(':') {
        authority.to_string()
    } else {
        format!("{authority}:80")
    };
    Ok(ParsedUrl {
        host_port,
        host_header: authority.to_string(),
        base_path,
    })
}

fn http_request(
    url: &ParsedUrl,
    method: &str,
    sub_path: &str,
    json_body: Option<&str>,
) -> Result<(u16, String), String> {
    let mut stream = TcpStream::connect(&url.host_port).map_err(|e| e.to_string())?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_nodelay(true);

    let full_path = format!("{}{}", url.base_path, sub_path);
    let body_bytes = json_body.unwrap_or("").as_bytes();
    let req = if json_body.is_some() {
        format!(
            "{method} {full_path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            url.host_header,
            body_bytes.len()
        )
    } else {
        format!(
            "{method} {full_path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            url.host_header
        )
    };
    stream
        .write_all(req.as_bytes())
        .map_err(|e| e.to_string())?;
    if !body_bytes.is_empty() {
        stream.write_all(body_bytes).map_err(|e| e.to_string())?;
    }

    let mut resp = Vec::with_capacity(1024);
    stream.read_to_end(&mut resp).map_err(|e| e.to_string())?;
    let hdr_end = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "Malformed HTTP response".to_string())?;
    let hdr_str = std::str::from_utf8(&resp[..hdr_end]).map_err(|e| e.to_string())?;
    let mut lines = hdr_str.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("Invalid status line: {status_line}"))?;

    let mut is_chunked = false;
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            if k.trim().eq_ignore_ascii_case("transfer-encoding")
                && v.to_ascii_lowercase().contains("chunked")
            {
                is_chunked = true;
            }
        }
    }

    let raw_body = &resp[hdr_end + 4..];
    let body_text = if is_chunked {
        decode_chunked_str(raw_body)
    } else {
        String::from_utf8_lossy(raw_body).into_owned()
    };
    Ok((status_code, body_text))
}

fn decode_chunked_str(mut data: &[u8]) -> String {
    let mut out = Vec::new();
    loop {
        let Some(pos) = data.windows(2).position(|w| w == b"\r\n") else {
            break;
        };
        let sz_raw = std::str::from_utf8(&data[..pos]).unwrap_or("").trim();
        let hex = sz_raw.split(';').next().unwrap_or("").trim();
        let Ok(len) = usize::from_str_radix(hex, 16) else {
            break;
        };
        data = &data[pos + 2..];
        if len == 0 || data.len() < len {
            break;
        }
        out.extend_from_slice(&data[..len]);
        data = if data.len() >= len + 2 {
            &data[len + 2..]
        } else {
            &[]
        };
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn register_with_env(url: &ParsedUrl, port: u16) -> Result<(), String> {
    let payload = format!("{{\"port\":{port}}}");
    let mut last_err = String::from("register failed");
    for attempt in 0..50u64 {
        match http_request(url, "POST", "/register", Some(&payload)) {
            Ok((status, _)) if (200..300).contains(&status) => return Ok(()),
            Ok((status, _)) => last_err = format!("register returned HTTP {status}"),
            Err(e) => last_err = e,
        }
        let backoff = (25 + attempt * 15).min(200);
        thread::sleep(Duration::from_millis(backoff));
    }
    Err(last_err)
}

fn wait_until_done(url: &ParsedUrl) {
    loop {
        if let Ok((status, body)) = http_request(url, "GET", "/done", None) {
            if (200..300).contains(&status) {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&body) {
                    if val.get("done").and_then(|v| v.as_bool()) == Some(true) {
                        return;
                    }
                }
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn main() {
    let env_url = env::var("MAKEFUN_ENV_URL").ok().filter(|s| !s.is_empty());
    let dev_port_raw = env::var("MAKEFUN_DEV_PORT").ok();

    if env_url.is_none() && dev_port_raw.is_none() {
        eprintln!("MAKEFUN_ENV_URL is required");
        process::exit(1);
    }

    let token = env::var("MAKEFUN_SHOP_TOKEN").unwrap_or_default();
    let ctx = AppContext::new(token);

    let bind_addr = if env_url.is_none() {
        let p = dev_port_raw
            .as_deref()
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0);
        format!("127.0.0.1:{p}")
    } else {
        "0.0.0.0:0".to_string()
    };

    let listener = match TcpListener::bind(&bind_addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind {bind_addr}: {e}");
            process::exit(1);
        }
    };
    let port = match listener.local_addr() {
        Ok(addr) => addr.port(),
        Err(e) => {
            eprintln!("Failed to read bound port: {e}");
            process::exit(1);
        }
    };

    ctx.spawn_pool();
    let accept_ctx = ctx.clone();
    thread::Builder::new()
        .name("forge-accept".to_string())
        .spawn(move || accept_ctx.run_accept_loop(listener))
        .expect("spawn accept loop");

    match env_url {
        None => {
            println!("listening on http://127.0.0.1:{port}");
            let _ = io::stdout().flush();
            loop {
                thread::sleep(Duration::from_secs(3600));
            }
        }
        Some(raw) => {
            let parsed = match parse_http_url(&raw) {
                Ok(u) => u,
                Err(e) => {
                    eprintln!("{e}");
                    process::exit(1);
                }
            };
            if let Err(e) = register_with_env(&parsed, port) {
                eprintln!("Registration failed: {e}");
                process::exit(1);
            }
            wait_until_done(&parsed);
            ctx.signal_shutdown();
            process::exit(0);
        }
    }
}

use std::io;
