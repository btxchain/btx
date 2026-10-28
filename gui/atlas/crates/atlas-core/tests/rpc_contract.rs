use atlas_core::{
    auth::CookieSource,
    operations::{PreparedStore, Request},
    rpc::{decode_response, Rpc},
};
use serde_json::{json, Value};
use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    thread,
};
fn cookie(dir: &tempfile::TempDir) -> CookieSource {
    let p = dir.path().join(".cookie");
    fs::write(&p, b"__cookie__:test-secret").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
    }
    CookieSource::new(p).unwrap()
}
#[test]
fn refuses_non_loopback_and_hostnames() {
    let d = tempfile::tempdir().unwrap();
    for e in [
        "example.com:8332",
        "192.0.2.1:8332",
        "127.0.0.1:0",
        "http://127.0.0.1:8332",
    ] {
        assert!(Rpc::new(e, cookie(&d)).is_err());
    }
}
#[test]
fn request_and_response_exact_wire() {
    let d = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    let server = thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut received = Vec::new();
        let mut buf = [0; 512];
        loop {
            let n = s.read(&mut buf).unwrap();
            assert!(n > 0);
            received.extend_from_slice(&buf[..n]);
            assert!(received.len() < 8192);
            if let Some(split) = received.windows(4).position(|v| v == b"\r\n\r\n") {
                let h = std::str::from_utf8(&received[..split]).unwrap();
                let length = h
                    .lines()
                    .find_map(|l| l.strip_prefix("Content-Length: "))
                    .unwrap()
                    .parse::<usize>()
                    .unwrap();
                if received.len() < split + 4 + length {
                    continue;
                }
                assert!(h.starts_with("POST /wallet/research%20wallet HTTP/1.1"));
                assert!(h.contains("Authorization: Basic "));
                let req: Value = serde_json::from_slice(&received[split + 4..]).unwrap();
                assert_eq!(req["method"], "getbalances");
                let body = format!(
                    "{{\"result\":{{\"precise\":0.00000001}},\"error\":null,\"id\":{}}}",
                    req["id"]
                );
                write!(
                    s,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .unwrap();
                break;
            }
        }
    });
    let rpc = Rpc::new(&endpoint, cookie(&d)).unwrap();
    let reply = rpc
        .call("getbalances", &json!([]), Some("research wallet"), 5)
        .unwrap();
    assert_eq!(reply["precise"].to_string(), "0.00000001");
    server.join().unwrap();
}
#[test]
fn framing_ambiguity_unknown() {
    let e = decode_response(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        1,
    )
    .unwrap_err();
    assert!(e.outcome_unknown);
}
#[test]
fn model_output_cannot_export_keys() {
    let mut s = PreparedStore::default();
    for m in ["dumpprivkey", "dumpwallet"] {
        assert!(s
            .prepare(
                Request {
                    method: m.into(),
                    params_json: "[]".into(),
                    wallet: None
                },
                1
            )
            .is_err());
    }
}
#[test]
fn approval_is_not_portable_across_connection() {
    let mut s = PreparedStore::default();
    let p = s
        .prepare(
            Request {
                method: "stop".into(),
                params_json: "[]".into(),
                wallet: None,
            },
            1,
        )
        .unwrap();
    assert!(s.consume(&p.id, 2).is_err());
    assert!(s.consume(&p.id, 1).is_err());
}
#[test]
fn native_review_keeps_timeout_hides_passphrase() {
    let r = Request {
        method: "walletpassphrase".into(),
        params_json: "[\"SECRET_PASSWORD\",30]".into(),
        wallet: Some("w".into()),
    };
    let s = r.summary().unwrap();
    assert!(!s.contains("SECRET_PASSWORD"));
    assert!(s.contains("30"));
}
