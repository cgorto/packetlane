//! Just enough HTTP/1.1 for a loopback-only server: request bytes in,
//! response bytes out. No sockets here.

use serde::Serialize;

/// Largest request line plus headers accepted.
pub const MAX_HEAD: usize = 16 * 1024;
/// Largest request body accepted.
pub const MAX_BODY: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: Method,
    /// The path, percent-decoded, without the query string.
    pub path: String,
    pub query: Vec<(String, String)>,
    /// Header names are lower-cased.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn param(&self, name: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    Complete(Request),
    /// More bytes are needed.
    Partial,
    /// The request is refused with this status and reason.
    Bad(u16, &'static str),
}

fn percent_decode(text: &str, plus_is_space: bool) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        match b {
            b'%' => {
                let hex = bytes.get(i + 1..i + 3)?;
                if !hex.iter().all(u8::is_ascii_hexdigit) {
                    return None;
                }
                let hex = std::str::from_utf8(hex).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 3;
            }
            b'+' if plus_is_space => {
                out.push(b' ');
                i += 1;
            }
            _ => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Parses one request from the start of `buf`.
pub fn parse_request(buf: &[u8]) -> Parsed {
    let Some(head_len) = find(buf, b"\r\n\r\n") else {
        return if buf.len() > MAX_HEAD {
            Parsed::Bad(431, "Request headers too large")
        } else {
            Parsed::Partial
        };
    };
    if head_len > MAX_HEAD {
        return Parsed::Bad(431, "Request headers too large");
    }
    let Ok(head) = std::str::from_utf8(&buf[..head_len]) else {
        return Parsed::Bad(400, "Request must be valid UTF-8");
    };
    let mut lines = head.split("\r\n");
    let mut parts = lines.next().unwrap_or("").split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Parsed::Bad(400, "Invalid request line");
    };
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Parsed::Bad(400, "Unsupported HTTP version");
    }
    let method = match method {
        "GET" => Method::Get,
        "POST" => Method::Post,
        _ => return Parsed::Bad(405, "Method not allowed"),
    };
    if !target.starts_with('/') {
        return Parsed::Bad(400, "Invalid request target");
    }
    let (raw_path, raw_query) = target.split_once('?').unwrap_or((target, ""));
    let Some(path) = percent_decode(raw_path, false) else {
        return Parsed::Bad(400, "Invalid request target");
    };
    let mut query = Vec::new();
    for pair in raw_query.split('&').filter(|p| !p.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let (Some(name), Some(value)) = (percent_decode(name, true), percent_decode(value, true))
        else {
            return Parsed::Bad(400, "Invalid query string");
        };
        query.push((name, value));
    }

    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Parsed::Bad(400, "Invalid header");
        };
        let name = name.to_ascii_lowercase();
        if name.is_empty() || name.contains(|c: char| c.is_whitespace()) {
            return Parsed::Bad(400, "Invalid header");
        }
        // A second copy of a header this server acts on would let two
        // readers of the request disagree about it.
        let single = matches!(
            name.as_str(),
            "host" | "content-length" | "origin" | "sec-fetch-site" | "x-packetlane-token"
        );
        if single && headers.iter().any(|(n, _)| *n == name) {
            return Parsed::Bad(400, "Repeated header");
        }
        headers.push((name, value.trim().to_string()));
    }
    if headers.iter().any(|(n, _)| n == "transfer-encoding") {
        return Parsed::Bad(400, "Transfer encoding is not supported");
    }
    let length = match headers.iter().find(|(n, _)| n == "content-length") {
        Some((_, v)) if !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) => {
            match v.parse::<usize>() {
                Ok(n) => n,
                Err(_) => return Parsed::Bad(400, "Invalid Content-Length"),
            }
        }
        Some(_) => return Parsed::Bad(400, "Invalid Content-Length"),
        None if method == Method::Post => return Parsed::Bad(411, "Content-Length required"),
        None => 0,
    };
    if length > MAX_BODY {
        return Parsed::Bad(413, "Request body too large");
    }
    let body_start = head_len + 4;
    let Some(body) = buf.get(body_start..body_start + length) else {
        return Parsed::Partial;
    };
    Parsed::Complete(Request {
        method,
        path,
        query,
        headers,
        body: body.to_vec(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

impl Response {
    pub fn json<T: Serialize>(status: u16, value: &T) -> Response {
        match serde_json::to_vec(value) {
            Ok(body) => Response {
                status,
                content_type: "application/json",
                body,
            },
            Err(_) => Response::error(500, "Could not encode response"),
        }
    }

    /// A JSON body of the form `{"error": "..."}`.
    pub fn error(status: u16, message: &str) -> Response {
        Response {
            status,
            content_type: "application/json",
            body: serde_json::json!({ "error": message })
                .to_string()
                .into_bytes(),
        }
    }

    pub fn html(body: &str) -> Response {
        Response {
            status: 200,
            content_type: "text/html; charset=utf-8",
            body: body.as_bytes().to_vec(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let reason = match self.status {
            200 => "OK",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            411 => "Length Required",
            413 => "Content Too Large",
            431 => "Request Header Fields Too Large",
            503 => "Service Unavailable",
            _ => "Error",
        };
        // The page is one self-contained document: it may run its own inline
        // script and style and call back to this server, and nothing else.
        let head = format!(
            "HTTP/1.1 {} {reason}\r\n\
             Content-Type: {}\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             Cache-Control: no-store\r\n\
             X-Content-Type-Options: nosniff\r\n\
             X-Frame-Options: DENY\r\n\
             Referrer-Policy: no-referrer\r\n\
             Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; \
             style-src 'unsafe-inline'; connect-src 'self'; img-src data:; base-uri 'none'; \
             form-action 'none'; frame-ancestors 'none'\r\n\r\n",
            self.status,
            self.content_type,
            self.body.len()
        );
        let mut out = head.into_bytes();
        out.extend_from_slice(&self.body);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete(text: &str) -> Request {
        match parse_request(text.as_bytes()) {
            Parsed::Complete(r) => r,
            other => panic!("expected a complete request, got {other:?}"),
        }
    }

    #[test]
    fn parses_a_get_with_query() {
        let r = complete(
            "GET /api/run?run=3&q=a+b%2Fc HTTP/1.1\r\nHost: 127.0.0.1:8737\r\nX-Packetlane-Token: abc\r\n\r\n",
        );
        assert_eq!(r.method, Method::Get);
        assert_eq!(r.path, "/api/run");
        assert_eq!(r.param("run"), Some("3"));
        assert_eq!(r.param("q"), Some("a b/c"));
        assert_eq!(r.header("host"), Some("127.0.0.1:8737"));
        assert_eq!(r.header("x-packetlane-token"), Some("abc"));
        assert!(r.body.is_empty());
    }

    #[test]
    fn waits_for_the_whole_body() {
        let text = "POST /api/query HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhel";
        assert_eq!(parse_request(text.as_bytes()), Parsed::Partial);
        let r = complete(&format!("{text}lo"));
        assert_eq!(r.body, b"hello");
        assert_eq!(
            parse_request(b"GET / HTTP/1.1\r\nHost: x\r\n"),
            Parsed::Partial
        );
    }

    #[test]
    fn refuses_what_it_does_not_handle() {
        let bad = |text: &str| match parse_request(text.as_bytes()) {
            Parsed::Bad(status, _) => status,
            other => panic!("expected a refusal for {text:?}, got {other:?}"),
        };
        assert_eq!(bad("DELETE / HTTP/1.1\r\n\r\n"), 405);
        assert_eq!(bad("GET / HTTP/2\r\n\r\n"), 400);
        assert_eq!(bad("GET http://x/ HTTP/1.1\r\n\r\n"), 400);
        assert_eq!(bad("GET /%zz HTTP/1.1\r\n\r\n"), 400);
        assert_eq!(bad("GET /?a=%f HTTP/1.1\r\n\r\n"), 400);
        assert_eq!(bad("GET / HTTP/1.1\r\nno colon\r\n\r\n"), 400);
        assert_eq!(bad("GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"), 400);
        assert_eq!(bad("POST / HTTP/1.1\r\nHost: a\r\n\r\n"), 411);
        assert_eq!(bad("POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n"), 400);
        assert_eq!(bad("POST / HTTP/1.1\r\nContent-Length: +2\r\n\r\n{}"), 400);
        assert_eq!(bad("GET /%+a HTTP/1.1\r\n\r\n"), 400);
        assert_eq!(
            bad(
                "GET / HTTP/1.1\r\nSec-Fetch-Site: same-origin\r\nSec-Fetch-Site: cross-site\r\n\r\n"
            ),
            400
        );
        assert_eq!(
            bad("GET / HTTP/1.1\r\nX-Packetlane-Token: a\r\nX-Packetlane-Token: b\r\n\r\n"),
            400
        );
        assert_eq!(
            bad("POST / HTTP/1.1\r\nContent-Length: 9999999\r\n\r\n"),
            413
        );
        assert_eq!(
            bad("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\n\r\nx"),
            400
        );
        let huge = format!("GET / HTTP/1.1\r\nX: {}\r\n", "a".repeat(MAX_HEAD));
        assert_eq!(bad(&huge), 431);
    }

    #[test]
    fn arbitrary_bytes_do_not_panic() {
        let mut x = 0x9E3779B9u32;
        for len in 0..300usize {
            let data: Vec<u8> = (0..len)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 17;
                    x ^= x << 5;
                    b"GET POST/?%&=: \r\nHTP1.0az9"[(x % 26) as usize]
                })
                .collect();
            let _ = parse_request(&data);
        }
    }

    #[test]
    fn response_bytes() {
        let bytes = Response::error(403, "no").to_bytes();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("HTTP/1.1 403 Forbidden\r\n"));
        assert!(text.contains("Content-Length: 14\r\n"));
        assert!(text.contains("frame-ancestors 'none'"));
        assert!(text.ends_with("\r\n\r\n{\"error\":\"no\"}"));
    }
}
