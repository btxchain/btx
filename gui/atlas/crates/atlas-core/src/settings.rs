//! Optimistic, owner-selected configuration edits. Never silently rewrite an existing
//! file after an external edit. Native review covers the complete key/value patch.
use crate::{files, hash, strict_json, Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, io::Write, path::Path};
const CATALOG: &str = include_str!("../../../schemas/node-settings.json");
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Edit {
    pub expected_hash: String,
    pub section: String,
    pub values: BTreeMap<String, String>,
}
#[derive(Serialize)]
pub struct Snapshot {
    pub hash: String,
    pub bytes: usize,
    pub values: BTreeMap<String, String>,
    pub section: String,
}
fn allowed(key: &str) -> bool {
    serde_json::from_str::<Value>(CATALOG)
        .ok()
        .and_then(|v| v.as_array().cloned())
        .is_some_and(|a| a.iter().any(|s| s["key"] == key))
}
fn section(s: &str) -> Result<()> {
    if !["", "main", "test", "testnet4", "signet", "regtest"].contains(&s) {
        return Err(Error::new("SECTION", "Unrecognized network config section"));
    }
    Ok(())
}
fn parse_values(text: &str, wanted: &str) -> BTreeMap<String, String> {
    let mut current = "";
    let mut values = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            current = &line[1..line.len() - 1];
            continue;
        }
        if current == wanted && !line.starts_with('#') {
            if let Some((k, v)) = line.split_once('=') {
                let k = k.trim();
                if allowed(k) {
                    values.insert(k.into(), v.trim().into());
                }
            }
        }
    }
    values
}
pub fn inspect(path: &Path, wanted: &str) -> Result<Snapshot> {
    section(wanted)?;
    let b = files::read_bounded(path, 1_048_576)?;
    let text = std::str::from_utf8(&b).map_err(|_| Error::new("CONFIG", "Config is not UTF-8"))?;
    Ok(Snapshot {
        hash: hash(&b),
        bytes: b.len(),
        values: parse_values(text, wanted),
        section: wanted.into(),
    })
}
pub fn render(text: &str, edit: &Edit) -> Result<String> {
    section(&edit.section)?;
    if edit.values.len() > 64 {
        return Err(Error::new("CONFIG", "Too many settings in one edit"));
    }
    for (k, v) in &edit.values {
        if !allowed(k) || v.len() > 1024 || v.chars().any(char::is_control) || v.contains('#') {
            return Err(Error::new(
                "CONFIG",
                "Unapproved key or multiline/comment value",
            ));
        }
    }
    let mut out = Vec::new();
    let mut current = String::new();
    let mut emitted = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            if current == edit.section && !emitted {
                for (k, v) in &edit.values {
                    out.push(format!("{k}={v}"));
                }
                emitted = true;
            }
            current = trimmed[1..trimmed.len() - 1].into();
        }
        if current == edit.section
            && !trimmed.starts_with('#')
            && trimmed
                .split_once('=')
                .is_some_and(|(k, _)| edit.values.contains_key(k.trim()))
        {
            continue;
        }
        out.push(line.to_owned());
    }
    if !emitted {
        if current != edit.section {
            out.push(format!("[{}]", edit.section));
        }
        for (k, v) in &edit.values {
            out.push(format!("{k}={v}"));
        }
    }
    let result = out.join("\n") + "\n";
    if result.len() > 1_048_576 {
        return Err(Error::new(
            "CONFIG_SIZE",
            "Resulting configuration exceeds budget",
        ));
    }
    Ok(result)
}
pub fn apply(path: &Path, edit: &Edit) -> Result<Snapshot> {
    let before = files::read_bounded(path, 1_048_576)?;
    if hash(&before) != edit.expected_hash {
        return Err(Error::new(
            "CONFIG_CONFLICT",
            "Configuration changed outside Atlas; read and review it again",
        ));
    }
    let text =
        std::str::from_utf8(&before).map_err(|_| Error::new("CONFIG", "Config is not UTF-8"))?;
    let after = render(text, edit)?;
    let parent = path
        .parent()
        .ok_or_else(|| Error::new("CONFIG", "Configuration has no parent directory"))?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|_| Error::new("CONFIG_WRITE", "Cannot stage config beside original"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|_| Error::new("PERMISSIONS", "Cannot restrict config permissions"))?;
    }
    tmp.write_all(after.as_bytes())
        .and_then(|_| tmp.as_file().sync_all())
        .map_err(|_| Error::new("CONFIG_WRITE", "Cannot persist staged config"))?;
    if hash(&files::read_bounded(path, 1_048_576)?) != edit.expected_hash {
        return Err(Error::new(
            "CONFIG_CONFLICT",
            "Configuration changed while staging",
        ));
    }
    tmp.persist(path)
        .map_err(|_| Error::new("CONFIG_WRITE", "Atomic config replacement failed"))?;
    #[cfg(unix)]
    {
        let _ = std::fs::File::open(parent).and_then(|f| f.sync_all());
    }
    inspect(path, &edit.section)
}
pub fn parse_edit(text: &str) -> Result<Edit> {
    serde_json::from_value(strict_json::parse(text.as_bytes(), 65536)?)
        .map_err(|_| Error::new("CONFIG", "Invalid edit contract"))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retains_other_sections() {
        let e = Edit {
            expected_hash: "".into(),
            section: "main".into(),
            values: BTreeMap::from([("dbcache".into(), "512".into())]),
        };
        let s = render("# user\n[main]\ndbcache=200\n[regtest]\ndbcache=100\n", &e).unwrap();
        assert!(s.contains("dbcache=512\n[regtest]\ndbcache=100"));
        assert!(!s.contains("dbcache=200"));
    }
    #[test]
    fn reject_injection() {
        let e = Edit {
            expected_hash: "".into(),
            section: "".into(),
            values: BTreeMap::from([("dbcache".into(), "1\nrpcpassword=x".into())]),
        };
        assert!(render("", &e).is_err());
    }
}
