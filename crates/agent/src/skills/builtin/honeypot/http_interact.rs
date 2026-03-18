//! HTTP medium-interaction honeypot handler.
//!
//! Parses real HTTP requests, serves a fake login page, captures POST
//! form submissions (credentials), and responds with an "invalid credentials"
//! page. Handles multiple requests per TCP connection (HTTP keep-alive).
//! No external HTTP crate required — manual parsing of HTTP/1.x.

use std::time::Duration;

use chrono::Utc;
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;

// ---------------------------------------------------------------------------
// Evidence types
// ---------------------------------------------------------------------------

/// One HTTP request captured from the attacker.
#[derive(Debug, Clone, Serialize)]
pub struct HttpRequestCapture {
    pub ts: String,
    pub method: String,
    pub path: String,
    /// Interesting headers: Host, User-Agent, Content-Type, Authorization.
    pub headers: Vec<(String, String)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_preview: Option<String>,
    /// Parsed form fields from urlencoded POST body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub form_fields: Option<Vec<(String, String)>>,
}

/// Evidence for one HTTP TCP connection.
#[derive(Debug, Clone, Serialize)]
pub struct HttpConnectionEvidence {
    pub requests: Vec<HttpRequestCapture>,
}

// ---------------------------------------------------------------------------
// Login page HTML (embedded — no file I/O needed)
// ---------------------------------------------------------------------------

const LOGIN_HTML_BODY: &str = r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Login</title>
<style>body{font-family:sans-serif;background:#f0f2f5;display:flex;justify-content:center;align-items:center;height:100vh}
.box{background:#fff;padding:2rem;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.15);min-width:320px}
h2{margin-top:0}input{width:100%;padding:.5rem;margin:.4rem 0 1rem;box-sizing:border-box;border:1px solid #ccc;border-radius:4px}
button{width:100%;padding:.6rem;background:#2563eb;color:#fff;border:none;border-radius:4px;cursor:pointer}
.err{color:#dc2626;margin-bottom:1rem}</style>
</head>
<body><div class="box">
<h2>&#128274; Sign In</h2>
<form method="POST" action="/login">
<label>Username<input name="username" type="text" autocomplete="username"></label>
<label>Password<input name="password" type="password" autocomplete="current-password"></label>
<button type="submit">Sign In</button>
</form>
</div></body></html>"#;

const LOGIN_FAILED_HTML_BODY: &str = r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Login</title>
<style>body{font-family:sans-serif;background:#f0f2f5;display:flex;justify-content:center;align-items:center;height:100vh}
.box{background:#fff;padding:2rem;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.15);min-width:320px}
h2{margin-top:0}input{width:100%;padding:.5rem;margin:.4rem 0 1rem;box-sizing:border-box;border:1px solid #ccc;border-radius:4px}
button{width:100%;padding:.6rem;background:#2563eb;color:#fff;border:none;border-radius:4px;cursor:pointer}
.err{color:#dc2626;margin-bottom:1rem}</style>
</head>
<body><div class="box">
<h2>&#128274; Sign In</h2>
<p class="err">Invalid username or password.</p>
<form method="POST" action="/login">
<label>Username<input name="username" type="text" autocomplete="username"></label>
<label>Password<input name="password" type="password" autocomplete="current-password"></label>
<button type="submit">Sign In</button>
</form>
</div></body></html>"#;

// ---------------------------------------------------------------------------
// Low-level HTTP helpers
// ---------------------------------------------------------------------------

/// Parsed HTTP/1.x request.
#[derive(Debug)]
struct RawRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    keep_alive: bool,
}

/// Read exactly one HTTP/1.x request from `stream`.
/// Returns `None` on EOF, timeout, or parse error.
async fn read_one_request(
    stream: &mut tokio::net::TcpStream,
    buf: &mut Vec<u8>,
    max_body: usize,
    timeout: Duration,
) -> Option<RawRequest> {
    // Read until we find the header terminator \r\n\r\n.
    let header_end = loop {
        if let Some(pos) = find_header_end(buf) {
            break pos;
        }
        if buf.len() > 16_384 {
            return None; // oversized headers
        }
        let mut tmp = [0u8; 1024];
        match tokio::time::timeout(timeout, stream.read(&mut tmp)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return None,
            Ok(Ok(n)) => buf.extend_from_slice(&tmp[..n]),
        }
    };

    let header_section = &buf[..header_end];
    let mut lines = header_section.split(|&b| b == b'\n');

    // Request line
    let req_line = lines.next()?;
    let req_line = trim_cr(req_line);
    let mut parts = req_line.splitn(3, |&b| b == b' ');
    let method = String::from_utf8_lossy(parts.next()?).trim().to_uppercase();
    let path = String::from_utf8_lossy(parts.next()?).trim().to_string();

    // Headers
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut content_length: usize = 0;
    let mut connection_close = false;
    for line in lines {
        let line = trim_cr(line);
        if line.is_empty() {
            break;
        }
        if let Some(colon) = line.iter().position(|&b| b == b':') {
            let name = String::from_utf8_lossy(&line[..colon]).trim().to_string();
            let value = String::from_utf8_lossy(&line[colon + 1..])
                .trim()
                .to_string();
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.parse().unwrap_or(0);
            }
            if name.eq_ignore_ascii_case("connection") {
                connection_close = value.eq_ignore_ascii_case("close");
            }
            headers.push((name, value));
        }
    }

    // Consume the header bytes from `buf`; the rest is body prefix.
    let consumed = header_end + 4; // +4 for \r\n\r\n
    let leftover = buf[consumed..].to_vec();
    buf.clear();
    buf.extend_from_slice(&leftover);

    // Read body up to content_length, capped at max_body.
    let body_want = content_length.min(max_body);
    let mut body: Vec<u8> = buf.drain(..buf.len().min(body_want)).collect();
    while body.len() < body_want {
        let need = body_want - body.len();
        let mut tmp = vec![0u8; need.min(4096)];
        match tokio::time::timeout(timeout, stream.read(&mut tmp)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => body.extend_from_slice(&tmp[..n]),
        }
    }

    let keep_alive = !connection_close && content_length < 1_000_000;

    Some(RawRequest {
        method,
        path,
        headers,
        body,
        keep_alive,
    })
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn trim_cr(b: &[u8]) -> &[u8] {
    if b.ends_with(b"\r") {
        &b[..b.len() - 1]
    } else {
        b
    }
}

// ---------------------------------------------------------------------------
// URL-encoded form parsing
// ---------------------------------------------------------------------------

fn parse_urlencoded(body: &[u8]) -> Vec<(String, String)> {
    let s = String::from_utf8_lossy(body);
    s.split('&')
        .filter_map(|pair| {
            let mut it = pair.splitn(2, '=');
            let k = it.next()?;
            let v = it.next().unwrap_or("");
            Some((url_decode(k), url_decode(v)))
        })
        .filter(|(k, _)| !k.is_empty())
        .collect()
}

fn url_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+' {
            out.push(' ');
            i += 1;
        } else if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(byte) = u8::from_str_radix(hex, 16) {
                    out.push(byte as char);
                    i += 3;
                    continue;
                }
            }
            out.push('%');
            i += 1;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// HTTP routing & response building
// ---------------------------------------------------------------------------

fn interesting_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    const KEEP: &[&str] = &[
        "host",
        "user-agent",
        "content-type",
        "authorization",
        "referer",
        "accept-language",
    ];
    headers
        .iter()
        .filter(|(name, _)| KEEP.iter().any(|k| name.eq_ignore_ascii_case(k)))
        .cloned()
        .collect()
}

fn is_form_post(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("content-type")
            && value
                .to_ascii_lowercase()
                .contains("application/x-www-form-urlencoded")
    })
}

fn body_preview(body: &[u8], limit: usize) -> String {
    let s = String::from_utf8_lossy(&body[..body.len().min(limit)]);
    // Sanitize: replace non-printable except spaces
    s.chars()
        .map(|c| if c.is_control() && c != ' ' { '.' } else { c })
        .collect()
}

fn http_200(body: &str) -> Vec<u8> {
    let len = body.len();
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {len}\r\nServer: nginx/1.24.0\r\nConnection: keep-alive\r\n\r\n{body}"
    )
    .into_bytes()
}

fn http_302(location: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"
    )
    .into_bytes()
}

fn http_404() -> Vec<u8> {
    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
}

/// Route one request and return the HTTP response bytes.
fn route(req: &RawRequest, capture: &mut HttpRequestCapture) -> Vec<u8> {
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/" | "/admin" | "/dashboard" | "/wp-admin" | "/phpmyadmin") => http_302("/login"),
        ("GET", "/login") => http_200(LOGIN_HTML_BODY),
        ("POST", "/login") => {
            // Parse credentials from form body.
            if is_form_post(&req.headers) {
                let fields = parse_urlencoded(&req.body);
                if !fields.is_empty() {
                    capture.form_fields = Some(fields);
                }
            }
            http_200(LOGIN_FAILED_HTML_BODY)
        }
        _ => http_404(),
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Handle one HTTP TCP connection with medium interaction.
///
/// Returns evidence (requests, form submissions). Handles up to `max_requests`
/// per connection. Each request read uses `req_timeout`.
pub(crate) async fn handle_connection(
    stream: &mut tokio::net::TcpStream,
    max_requests: usize,
    max_body_bytes: usize,
    transcript_preview_bytes: usize,
    req_timeout: Duration,
) -> HttpConnectionEvidence {
    let mut requests: Vec<HttpRequestCapture> = Vec::new();
    let mut buf: Vec<u8> = Vec::with_capacity(4096);

    for _ in 0..max_requests {
        match read_one_request(stream, &mut buf, max_body_bytes, req_timeout).await {
            None => break,
            Some(req) => {
                debug!(method = %req.method, path = %req.path, "honeypot HTTP request");

                let form_fields_preview: Option<Vec<(String, String)>> = None;
                let bp = if req.body.is_empty() {
                    None
                } else {
                    Some(body_preview(&req.body, transcript_preview_bytes))
                };

                let mut capture = HttpRequestCapture {
                    ts: Utc::now().to_rfc3339(),
                    method: req.method.clone(),
                    path: req.path.clone(),
                    headers: interesting_headers(&req.headers),
                    body_preview: bp,
                    form_fields: form_fields_preview,
                };

                let response = route(&req, &mut capture);
                let keep_alive = req.keep_alive;

                if let Err(e) = stream.write_all(&response).await {
                    debug!("honeypot HTTP write error: {e}");
                    requests.push(capture);
                    break;
                }
                requests.push(capture);

                if !keep_alive {
                    break;
                }
            }
        }
    }

    HttpConnectionEvidence { requests }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_urlencoded_basic() {
        let body = b"username=admin&password=secret%20123";
        let fields = parse_urlencoded(body);
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0], ("username".to_string(), "admin".to_string()));
        assert_eq!(
            fields[1],
            ("password".to_string(), "secret 123".to_string())
        );
    }

    #[test]
    fn parse_urlencoded_plus_space() {
        let body = b"q=hello+world";
        let fields = parse_urlencoded(body);
        assert_eq!(fields[0].1, "hello world");
    }

    #[test]
    fn parse_urlencoded_empty() {
        let fields = parse_urlencoded(b"");
        assert!(fields.is_empty());
    }

    #[test]
    fn find_header_end_detects_separator() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let pos = find_header_end(data).expect("should find \\r\\n\\r\\n");
        assert_eq!(&data[pos..pos + 4], b"\r\n\r\n");
    }

    #[test]
    fn find_header_end_none_without_separator() {
        assert!(find_header_end(b"GET / HTTP/1.1\r\nHost: x\r\n").is_none());
    }

    #[test]
    fn route_get_login_returns_login_page() {
        let req = RawRequest {
            method: "GET".into(),
            path: "/login".into(),
            headers: vec![],
            body: vec![],
            keep_alive: true,
        };
        let mut cap = HttpRequestCapture {
            ts: String::new(),
            method: req.method.clone(),
            path: req.path.clone(),
            headers: vec![],
            body_preview: None,
            form_fields: None,
        };
        let resp = route(&req, &mut cap);
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.contains("200 OK"));
        assert!(resp_str.contains("<form"));
    }

    #[test]
    fn route_post_login_captures_credentials() {
        let body = b"username=hacker&password=p@$$w0rd";
        let req = RawRequest {
            method: "POST".into(),
            path: "/login".into(),
            headers: vec![(
                "Content-Type".into(),
                "application/x-www-form-urlencoded".into(),
            )],
            body: body.to_vec(),
            keep_alive: false,
        };
        let mut cap = HttpRequestCapture {
            ts: String::new(),
            method: req.method.clone(),
            path: req.path.clone(),
            headers: vec![],
            body_preview: None,
            form_fields: None,
        };
        let resp = route(&req, &mut cap);
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.contains("Invalid username or password"));
        let fields = cap.form_fields.unwrap();
        assert_eq!(
            fields.iter().find(|(k, _)| k == "username").unwrap().1,
            "hacker"
        );
        assert_eq!(
            fields.iter().find(|(k, _)| k == "password").unwrap().1,
            "p@$$w0rd"
        );
    }

    #[test]
    fn route_root_redirects_to_login() {
        let req = RawRequest {
            method: "GET".into(),
            path: "/".into(),
            headers: vec![],
            body: vec![],
            keep_alive: true,
        };
        let mut cap = HttpRequestCapture {
            ts: String::new(),
            method: req.method.clone(),
            path: req.path.clone(),
            headers: vec![],
            body_preview: None,
            form_fields: None,
        };
        let resp = route(&req, &mut cap);
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.contains("302 Found"));
        assert!(resp_str.contains("/login"));
    }

    #[test]
    fn route_unknown_returns_404() {
        let req = RawRequest {
            method: "GET".into(),
            path: "/secret-api".into(),
            headers: vec![],
            body: vec![],
            keep_alive: true,
        };
        let mut cap = HttpRequestCapture {
            ts: String::new(),
            method: req.method.clone(),
            path: req.path.clone(),
            headers: vec![],
            body_preview: None,
            form_fields: None,
        };
        let resp = route(&req, &mut cap);
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.contains("404 Not Found"));
    }

    #[test]
    fn body_preview_sanitizes() {
        let raw = b"username=x\x00\x01\x02&password=y";
        let preview = body_preview(raw, 64);
        assert!(!preview.contains('\x00'));
    }

    #[test]
    fn interesting_headers_filters() {
        let headers = vec![
            ("Host".into(), "example.com".into()),
            ("User-Agent".into(), "curl/8.0".into()),
            ("X-Custom".into(), "ignored".into()),
            ("Authorization".into(), "Basic xyz".into()),
        ];
        let filtered = interesting_headers(&headers);
        assert!(filtered.iter().any(|(k, _)| k == "Host"));
        assert!(filtered.iter().any(|(k, _)| k == "User-Agent"));
        assert!(filtered.iter().any(|(k, _)| k == "Authorization"));
        assert!(!filtered.iter().any(|(k, _)| k == "X-Custom"));
    }
}
