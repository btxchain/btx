//! Deliberately narrow HTTP/1.1 transport: literal loopback only, no DNS, TLS,
//! proxy, redirects, cookie jar, compression, or remote fetch facility.
use crate::{auth::CookieSource, strict_json, Error, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
static SEQUENCE: AtomicU64 = AtomicU64::new(1);
pub const READ_SECONDS: u64 = 20;
#[derive(Clone)]
pub struct Rpc {
    pub address: SocketAddr,
    pub cookie: CookieSource,
}
impl Rpc {
    pub fn new(endpoint: &str, cookie: CookieSource) -> Result<Self> {
        let address: SocketAddr = endpoint.parse().map_err(|_| {
            Error::new(
                "ENDPOINT",
                "Use a literal loopback IP and port, not a hostname or URL",
            )
        })?;
        if !address.ip().is_loopback() || address.port() == 0 {
            return Err(Error::new(
                "ENDPOINT",
                "Only loopback RPC endpoints are permitted",
            ));
        }
        Ok(Self { address, cookie })
    }
    pub fn call(
        &self,
        method: &str,
        params: &Value,
        wallet: Option<&str>,
        seconds: u64,
    ) -> Result<Value> {
        if method.is_empty()
            || method.len() > 96
            || !method
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(Error::new("METHOD", "Invalid RPC method"));
        }
        let id = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let body = Zeroizing::new(
            serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))
                .map_err(|_| Error::new("JSON", "Request serialization failed"))?,
        );
        if body.len() > strict_json::MAX_REQUEST {
            return Err(Error::new("REQUEST_SIZE", "RPC request exceeds budget"));
        }
        let path = match wallet {
            Some(w) if !w.is_empty() => {
                if w.len() > 512 || w.chars().any(char::is_control) {
                    return Err(Error::new("WALLET", "Invalid wallet name"));
                }
                format!("/wallet/{}", percent_component(w))
            }
            _ => "/".into(),
        };
        let auth = self.cookie.load()?;
        let authorization = Zeroizing::new(STANDARD.encode(auth.as_bytes()));
        let header=Zeroizing::new(format!("POST {path} HTTP/1.1\r\nHost: {}\r\nAuthorization: Basic {}\r\nContent-Type: application/json\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",self.address,&*authorization,body.len()));
        let total = Duration::from_secs(seconds.clamp(1, 180));
        let deadline = Instant::now() + total;
        let mut stream = TcpStream::connect_timeout(&self.address, Duration::from_secs(3))
            .map_err(|_| Error::new("NODE_UNAVAILABLE", "Cannot connect to local BTX RPC"))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .map_err(|_| Error::new("SOCKET", "Cannot set write deadline"))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .map_err(|_| Error::new("SOCKET", "Cannot set read deadline"))?;
        // After the first write begins, delivery may have happened even if an I/O call fails.
        stream
            .write_all(header.as_bytes())
            .and_then(|_| stream.write_all(&body))
            .map_err(|_| {
                Error::unknown("Request delivery failed; do not automatically retry a mutation")
            })?;
        let mut response = Vec::with_capacity(8192);
        let mut buf = [0u8; 8192];
        loop {
            if Instant::now() >= deadline {
                return Err(Error::unknown(
                    "RPC deadline expired; the native operation may still be running",
                ));
            }
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if response.len() + n > strict_json::MAX_RESPONSE + 32768 {
                        return Err(Error::unknown("RPC response exceeded the byte budget"));
                    }
                    response.extend_from_slice(&buf[..n]);
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue
                }
                Err(_) => {
                    return Err(Error::unknown(
                        "Connection ended without a complete RPC response",
                    ))
                }
            }
        }
        decode_response(&response, id)
    }
}
pub fn percent_component(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}
pub fn decode_response(bytes: &[u8], expected_id: u64) -> Result<Value> {
    let split = bytes
        .windows(4)
        .position(|x| x == b"\r\n\r\n")
        .ok_or_else(|| Error::unknown("Incomplete HTTP header"))?;
    if split > 16384 {
        return Err(Error::unknown("Oversized HTTP header"));
    }
    let header = std::str::from_utf8(&bytes[..split])
        .map_err(|_| Error::unknown("Invalid HTTP header encoding"))?;
    let mut lines = header.split("\r\n");
    let status = lines
        .next()
        .unwrap_or("")
        .split_ascii_whitespace()
        .nth(1)
        .and_then(|x| x.parse::<u16>().ok())
        .ok_or_else(|| Error::unknown("Invalid HTTP status"))?;
    if (300..400).contains(&status) {
        return Err(Error::new(
            "REDIRECT_REFUSED",
            "Local RPC redirects are not followed",
        ));
    }
    if status == 401 || status == 403 {
        return Err(Error::new("AUTH", "RPC authentication refused"));
    }
    let mut length = None;
    let mut chunked = false;
    let mut encoding = false;
    for line in lines {
        let (k, v) = line
            .split_once(':')
            .ok_or_else(|| Error::unknown("Malformed HTTP header"))?;
        let v = v.trim();
        match k.to_ascii_lowercase().as_str() {
            "content-length" => {
                if length.is_some() {
                    return Err(Error::unknown("Duplicate Content-Length"));
                }
                length = Some(
                    v.parse::<usize>()
                        .map_err(|_| Error::unknown("Invalid body length"))?,
                );
            }
            "transfer-encoding" => {
                if chunked || !v.eq_ignore_ascii_case("chunked") {
                    return Err(Error::unknown("Unsupported transfer encoding"));
                }
                chunked = true;
            }
            "content-encoding" => {
                if encoding || !v.eq_ignore_ascii_case("identity") {
                    return Err(Error::unknown("Compressed RPC response refused"));
                }
                encoding = true;
            }
            _ => {}
        }
    }
    if chunked && length.is_some() {
        return Err(Error::unknown("Ambiguous HTTP message framing"));
    }
    let payload = &bytes[split + 4..];
    let decoded;
    let body = if chunked {
        decoded = decode_chunks(payload)?;
        &decoded[..]
    } else {
        if let Some(n) = length {
            if n != payload.len() {
                return Err(Error::unknown("Truncated or overlong HTTP body"));
            }
        }
        payload
    };
    if !(200..300).contains(&status) && status != 500 {
        return Err(Error::new(
            "HTTP",
            format!("Local node returned HTTP {status}"),
        ));
    }
    let value = strict_json::parse(body, strict_json::MAX_RESPONSE)
        .map_err(|_| Error::unknown("RPC response was not bounded strict JSON"))?;
    if value.get("id").and_then(Value::as_u64) != Some(expected_id) {
        return Err(Error::unknown("RPC response ID mismatch"));
    }
    if let Some(e) = value.get("error").filter(|x| !x.is_null()) {
        let code = e
            .get("code")
            .map(Value::to_string)
            .unwrap_or_else(|| "UNKNOWN".into());
        let message = e
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("Node rejected request");
        return Err(Error::new(
            &format!("RPC_{code}"),
            crate::safe_text(message, 1024),
        ));
    }
    value
        .get("result")
        .cloned()
        .ok_or_else(|| Error::unknown("RPC result missing"))
}
fn decode_chunks(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut pos = 0;
    let mut out = Vec::new();
    let mut chunks = 0;
    loop {
        chunks += 1;
        if chunks > 65536 {
            return Err(Error::unknown("Too many HTTP chunks"));
        }
        let offset = bytes
            .get(pos..)
            .and_then(|b| b.windows(2).position(|x| x == b"\r\n"))
            .ok_or_else(|| Error::unknown("Missing chunk length"))?;
        if offset > 64 {
            return Err(Error::unknown("Chunk header too long"));
        }
        let line = std::str::from_utf8(&bytes[pos..pos + offset])
            .map_err(|_| Error::unknown("Invalid chunk header"))?;
        if !line.bytes().all(|x| x.is_ascii_hexdigit()) || line.is_empty() {
            return Err(Error::unknown("Chunk extensions/invalid length refused"));
        }
        let n =
            usize::from_str_radix(line, 16).map_err(|_| Error::unknown("Chunk length overflow"))?;
        pos += offset + 2;
        if n == 0 {
            if bytes.get(pos..) != Some(&b"\r\n"[..]) {
                return Err(Error::unknown("Unexpected HTTP trailers"));
            }
            return Ok(out);
        }
        if n > strict_json::MAX_RESPONSE.saturating_sub(out.len()) {
            return Err(Error::unknown("Chunk body exceeds byte budget"));
        }
        let end = pos
            .checked_add(n)
            .ok_or_else(|| Error::unknown("Chunk overflow"))?;
        if bytes.get(end..end + 2) != Some(&b"\r\n"[..]) {
            return Err(Error::unknown("Truncated chunk"));
        }
        out.extend_from_slice(&bytes[pos..end]);
        pos = end + 2;
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encode_wallet() {
        assert_eq!(percent_component("../x?y"), "..%2Fx%3Fy");
    }
    #[test]
    fn response() {
        let b = b"{\"result\":1,\"error\":null,\"id\":1}";
        let h = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", b.len());
        let mut v = h.into_bytes();
        v.extend(b);
        assert_eq!(decode_response(&v, 1).unwrap(), 1);
        assert!(decode_response(&v, 2).unwrap_err().outcome_unknown);
    }
    #[test]
    fn chunked() {
        assert_eq!(decode_chunks(b"3\r\nabc\r\n0\r\n\r\n").unwrap(), b"abc");
        assert!(decode_chunks(b"4\r\nabc\r\n0\r\n\r\n").is_err());
    }
    #[test]
    fn redirects() {
        assert_eq!(
            decode_response(
                b"HTTP/1.1 302 Found\r\nLocation: http://example.com/\r\n\r\n",
                1
            )
            .unwrap_err()
            .code,
            "REDIRECT_REFUSED"
        );
    }
}
