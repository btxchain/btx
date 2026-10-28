use crate::{hash, now_ms, strict_json, Error, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::PathBuf,
};
const MAX_LOG: usize = 16 * 1024 * 1024;
#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub sequence: u64,
    pub time_ms: u64,
    pub operation_id: String,
    pub method: String,
    pub phase: String,
    pub previous: String,
    pub hash: String,
}
pub struct Journal {
    path: PathBuf,
    last: String,
    sequence: u64,
    entries: Vec<Entry>,
}
impl Journal {
    pub fn open(path: PathBuf) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|_| Error::new("JOURNAL", "Cannot create audit directory"))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                    .map_err(|_| Error::new("JOURNAL", "Cannot protect audit directory"))?;
            }
        }
        let mut j = Self {
            path,
            last: "0".repeat(64),
            sequence: 0,
            entries: Vec::new(),
        };
        if j.path.exists() {
            let meta = fs::symlink_metadata(&j.path)
                .map_err(|_| Error::new("JOURNAL", "Audit metadata unavailable"))?;
            if meta.file_type().is_symlink() || !meta.is_file() || meta.len() > MAX_LOG as u64 {
                return Err(Error::new(
                    "JOURNAL",
                    "Audit file is unsafe or exceeds its retention budget",
                ));
            }
            let mut data = Vec::new();
            fs::File::open(&j.path)
                .and_then(|f| f.take(MAX_LOG as u64 + 1).read_to_end(&mut data))
                .map_err(|_| Error::new("JOURNAL", "Cannot read audit journal"))?;
            if !data.is_empty() && data.last() != Some(&b'\n') {
                return Err(Error::new(
                    "JOURNAL_TRUNCATED",
                    "Audit tail is incomplete; preserve and repair before issuing more operations",
                ));
            }
            for line in data.split(|b| *b == b'\n').filter(|x| !x.is_empty()) {
                let value = strict_json::parse(line, 8192)?;
                let e: Entry = serde_json::from_value(value)
                    .map_err(|_| Error::new("JOURNAL", "Invalid audit row"))?;
                if e.sequence != j.sequence + 1 || e.previous != j.last || entry_hash(&e) != e.hash
                {
                    return Err(Error::new(
                        "JOURNAL_INTEGRITY",
                        "Audit chain does not verify",
                    ));
                }
                j.sequence = e.sequence;
                j.last = e.hash.clone();
                j.entries.push(e);
            }
        }
        Ok(j)
    }
    pub fn append(&mut self, id: &str, method: &str, phase: &str) -> Result<()> {
        if id.len() > 128 || method.len() > 96 || phase.len() > 32 {
            return Err(Error::new("JOURNAL", "Invalid event identity"));
        }
        let mut e = Entry {
            sequence: self.sequence + 1,
            time_ms: now_ms(),
            operation_id: id.into(),
            method: method.into(),
            phase: phase.into(),
            previous: self.last.clone(),
            hash: String::new(),
        };
        e.hash = entry_hash(&e);
        let mut line =
            serde_json::to_vec(&e).map_err(|_| Error::new("JOURNAL", "Cannot serialize event"))?;
        line.push(b'\n');
        if fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0) + line.len() as u64
            > MAX_LOG as u64
        {
            return Err(Error::new(
                "JOURNAL_FULL",
                "Export/archive the audit log before more operations",
            ));
        }
        if fs::symlink_metadata(&self.path).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(Error::new("JOURNAL", "Audit symlinks are refused"));
        }
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut f = options
            .open(&self.path)
            .map_err(|_| Error::new("JOURNAL", "Cannot open audit log"))?;
        f.write_all(&line).and_then(|_| f.sync_all()).map_err(|_| {
            Error::new(
                "JOURNAL",
                "Audit persistence failed; mutation is not authorized",
            )
        })?;
        self.sequence = e.sequence;
        self.last = e.hash.clone();
        self.entries.push(e);
        Ok(())
    }
    pub fn tail(&self, limit: usize) -> Vec<Entry> {
        self.entries
            .iter()
            .rev()
            .take(limit.min(512))
            .cloned()
            .collect()
    }
    pub fn unresolved(&self) -> Vec<Entry> {
        let mut state = std::collections::BTreeMap::new();
        for e in &self.entries {
            state.insert(e.operation_id.clone(), e);
        }
        state
            .values()
            .filter(|e| matches!(e.phase.as_str(), "SUBMITTED" | "UNKNOWN"))
            .map(|e| (*e).clone())
            .collect()
    }
    pub fn checkpoint(&self) -> &str {
        &self.last
    }
}
fn entry_hash(e: &Entry) -> String {
    hash(
        format!(
            "BTX_ATLAS_AUDIT_1\0{}\0{}\0{}\0{}\0{}\0{}",
            e.sequence, e.time_ms, e.operation_id, e.method, e.phase, e.previous
        )
        .as_bytes(),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reload() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("audit.jsonl");
        let mut j = Journal::open(p.clone()).unwrap();
        j.append("id", "walletlock", "SUBMITTED").unwrap();
        assert_eq!(j.unresolved().len(), 1);
        j.append("id", "walletlock", "SUCCEEDED").unwrap();
        assert!(j.unresolved().is_empty());
        let r = Journal::open(p).unwrap();
        assert_eq!(j.checkpoint(), r.checkpoint());
    }
    #[test]
    fn corrupt() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a");
        fs::write(&p, b"{\"truncated\":").unwrap();
        assert!(Journal::open(p).is_err());
    }
}
