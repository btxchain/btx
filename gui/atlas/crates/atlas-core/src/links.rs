//! Startup arguments become a preview only. A file is not executed.
use crate::files;
use std::path::PathBuf;

pub fn preview_target(value: &str) -> Option<String> {
    let value = value.trim();
    if uri_ok(value) {
        return Some(value.to_owned());
    }
    // macOS hands a document opened from Finder over as a file URL, not as a path.
    let path = match value.strip_prefix("file://") {
        Some(rest) => file_url_path(rest)?,
        None => PathBuf::from(value),
    };
    let name = path.file_name()?.to_str()?;
    if !name.to_ascii_lowercase().ends_with(".btx") || name.len() < 5 {
        return None;
    }
    let bytes = files::read_bounded(&path, 4096).ok()?;
    let text = String::from_utf8(bytes).ok()?;
    let text = text.trim();
    if text.lines().count() != 1 || !uri_ok(text) {
        return None;
    }
    Some(text.to_owned())
}

/// The local path of a file URL: no host but `localhost`, no query or fragment, and percent
/// escapes decoded, except an escaped `/` or NUL.
fn file_url_path(rest: &str) -> Option<PathBuf> {
    let rest = rest.strip_prefix("localhost").unwrap_or(rest);
    if !rest.starts_with('/') || rest.contains(['?', '#']) {
        return None;
    }
    let mut bytes = Vec::with_capacity(rest.len());
    let mut input = rest.bytes();
    while let Some(b) = input.next() {
        if b != b'%' {
            bytes.push(b);
            continue;
        }
        let high = char::from(input.next()?).to_digit(16)?;
        let low = char::from(input.next()?).to_digit(16)?;
        let byte = u8::try_from(high * 16 + low).ok()?;
        if byte == b'/' || byte == 0 {
            return None;
        }
        bytes.push(byte);
    }
    let path = String::from_utf8(bytes).ok()?;
    Some(PathBuf::from(if cfg!(windows) {
        drive_path(&path)
    } else {
        &path
    }))
}

/// A Windows file URL puts a `/` before the drive: `file:///D:/x.btx` names `D:/x.btx`.
fn drive_path(path: &str) -> &str {
    match path.as_bytes() {
        [b'/', drive, b':', b'/', ..] if drive.is_ascii_alphabetic() => &path[1..],
        _ => path,
    }
}

fn uri_ok(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4096
        && (value.starts_with("btx:") || value.starts_with("btx-p2p:"))
        && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    #[test]
    fn uri_is_kept_and_a_btx_file_must_hold_one_uri() {
        assert_eq!(
            preview_target("btx:address?amount=0.00000001").as_deref(),
            Some("btx:address?amount=0.00000001")
        );
        assert!(preview_target("https://example.invalid").is_none());
        let dir = std::env::temp_dir().join(format!("atlas-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ok = dir.join("request.btx");
        let mut file = std::fs::File::create(&ok).unwrap();
        writeln!(
            file,
            "btx-p2p://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst.onion:8333"
        )
        .unwrap();
        assert!(preview_target(&ok.to_string_lossy())
            .unwrap()
            .starts_with("btx-p2p://"));
        let bad = dir.join("note.btx");
        std::fs::write(&bad, "not a link\nbtx:second").unwrap();
        assert!(preview_target(&bad.to_string_lossy()).is_none());
        let other = dir.join("note.txt");
        std::fs::write(&other, "btx:address").unwrap();
        assert!(preview_target(&other.to_string_lossy()).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
    #[test]
    fn a_file_url_from_finder_reads_the_same_file() {
        let dir = std::env::temp_dir().join(format!("atlas-link-url-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("Atlas Request.btx"), "btx:address?amount=0.5\n").unwrap();
        let mut path = dir
            .join("Atlas Request.btx")
            .to_string_lossy()
            .replace('\\', "/");
        if !path.starts_with('/') {
            path.insert(0, '/');
        }
        let path = path.replace(' ', "%20");
        for url in [format!("file://{path}"), format!("file://localhost{path}")] {
            assert_eq!(
                preview_target(&url).as_deref(),
                Some("btx:address?amount=0.5"),
                "{url}"
            );
        }
        for url in [
            format!("file://example.invalid{path}"),
            format!("file://{path}?x"),
            format!("file://{path}#x"),
            format!("file://{}", path.replace("/Atlas%20", "%2FAtlas%20")),
            format!("file://{}", path.replace("%20", "%00")),
            format!("file://{}", path.replace("%20", "%2")),
            format!("file://{}", path.replace("%20", "%zz")),
            "file://Atlas%20Request.btx".to_owned(),
        ] {
            assert!(preview_target(&url).is_none(), "{url}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
    #[test]
    fn a_windows_file_url_drops_the_slash_before_the_drive() {
        assert_eq!(
            drive_path("/D:/btx/Atlas Request.btx"),
            "D:/btx/Atlas Request.btx"
        );
        assert_eq!(drive_path("/c:/r.btx"), "c:/r.btx");
        for path in [
            "/Users/a/r.btx",
            "/D/r.btx",
            "/1:/r.btx",
            "/D:",
            "/D:r.btx",
            "//D:/r.btx",
        ] {
            assert_eq!(drive_path(path), path);
        }
    }
}
