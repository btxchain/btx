//! Startup arguments become a preview only. A file is not executed.
use crate::files;
use std::path::Path;

pub fn preview_target(value: &str) -> Option<String> {
    let value = value.trim();
    if uri_ok(value) {
        return Some(value.to_owned());
    }
    let path = Path::new(value);
    let name = path.file_name()?.to_str()?;
    if !name.to_ascii_lowercase().ends_with(".btx") || name.len() < 5 {
        return None;
    }
    let bytes = files::read_bounded(path, 4096).ok()?;
    let text = String::from_utf8(bytes).ok()?;
    let text = text.trim();
    if text.lines().count() != 1 || !uri_ok(text) {
        return None;
    }
    Some(text.to_owned())
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
}
