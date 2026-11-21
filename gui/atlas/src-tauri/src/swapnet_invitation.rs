//! Inert startup-link inbox. Reading an invitation never dials or authorizes funds.
use std::sync::{Mutex, OnceLock};
const PREFIX: &str = "btx://swapnet/v1/";
const MAX_LINK: usize = 32768;
static INBOX: OnceLock<Mutex<Vec<String>>> = OnceLock::new();

fn admissible(value: &str) -> bool {
    value.starts_with(PREFIX)
        && value.len() <= MAX_LINK
        && value.len() > PREFIX.len()
        && value[PREFIX.len()..].bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn inbox() -> &'static Mutex<Vec<String>> {
    INBOX.get_or_init(|| {
        let mut pending = Vec::new();
        for arg in std::env::args().skip(1).take(32) {
            // Reuse Atlas's bounded .btx/file-URL handling. This is only a preview.
            if let Some(uri) = atlas_core::links::preview_target(&arg) {
                if admissible(&uri) && pending.len() < 8 && !pending.contains(&uri) {
                    pending.push(uri);
                }
            }
        }
        Mutex::new(pending)
    })
}

/// Existing native open-file/deep-link dispatch may forward a URI here. No RPC.
pub fn enqueue(uri: &str) -> bool {
    if !admissible(uri) { return false; }
    let Ok(mut pending) = inbox().lock() else { return false; };
    if pending.contains(&uri.to_owned()) { return true; }
    if pending.len() == 8 { return false; }
    pending.push(uri.to_owned());
    true
}

#[tauri::command]
pub fn atlas_take_swapnet_invites() -> Vec<String> {
    // The frontend receives untrusted text, not a verified provider or capability.
    match inbox().lock() {
        Ok(mut pending) => std::mem::take(&mut *pending),
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn only_bounded_canonical_transport_text() {
        assert!(admissible("btx://swapnet/v1/Abc_-123"));
        for value in ["https://example.org", "btx://swapnet/v1/", "btx://swapnet/v1/a%2fb", "btx://swapnet/v1/a\nb", "btx://swapnet/v1/abc="] {
            assert!(!admissible(value));
        }
        assert!(!admissible(&format!("{}{}", PREFIX, "a".repeat(MAX_LINK))));
    }
}
