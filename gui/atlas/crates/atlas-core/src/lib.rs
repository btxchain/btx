#![forbid(unsafe_code)]
//! BTX Atlas authority core. No renderer, JavaScript engine, shell, or remote provider.
//! The node remains the source of consensus, wallet keys, model authority and evidence.
pub mod agent;
pub mod amount;
pub mod auth;
pub mod files;
pub mod journal;
pub mod links;
pub mod money;
pub mod operations;
pub mod rpc;
pub mod settings;
pub mod strict_json;

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize)]
pub struct Error {
    pub code: String,
    pub message: String,
    /// A transport failure after submission must never be interpreted as rejection.
    pub outcome_unknown: bool,
}
impl Error {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_owned(),
            message: message.into(),
            outcome_unknown: false,
        }
    }
    pub fn unknown(message: impl Into<String>) -> Self {
        Self {
            code: "OUTCOME_UNKNOWN".into(),
            message: message.into(),
            outcome_unknown: true,
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}
pub fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
pub fn random_id() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|_| Error::new("ENTROPY", "Operating-system entropy unavailable"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
pub fn safe_text(value: &str, limit: usize) -> String {
    value
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .take(limit)
        .collect()
}
