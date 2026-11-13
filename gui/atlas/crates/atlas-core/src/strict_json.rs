//! Structural preflight prevents duplicate/prototype keys before serde_json parses
//! arbitrary-precision numbers. Bounds apply before deserialization allocates trees.
use crate::{Error, Result};
use serde_json::Value;
use std::collections::HashSet;
pub const MAX_REQUEST: usize = 262_144;
pub const MAX_RESPONSE: usize = 4 * 1024 * 1024;
struct Scan<'a> {
    b: &'a [u8],
    i: usize,
    nodes: usize,
}
impl Scan<'_> {
    fn fail<T>(&self, msg: &str) -> Result<T> {
        Err(Error::new("JSON", format!("{msg} at byte {}", self.i)))
    }
    fn ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\r' | b'\n' | b'\t') {
            self.i += 1;
        }
    }
    fn string(&mut self) -> Result<String> {
        let start = self.i;
        self.i += 1;
        while self.i < self.b.len() {
            match self.b[self.i] {
                b'"' => {
                    self.i += 1;
                    return serde_json::from_slice(&self.b[start..self.i])
                        .map_err(|_| Error::new("JSON", "Invalid JSON string"));
                }
                b'\\' => {
                    self.i += 1;
                    if self.i >= self.b.len() {
                        return self.fail("Incomplete escape");
                    }
                    self.i += 1;
                }
                0..=31 => return self.fail("Control in string"),
                _ => self.i += 1,
            }
        }
        self.fail("Unterminated string")
    }
    fn value(&mut self, depth: usize) -> Result<()> {
        self.ws();
        self.nodes += 1;
        if depth > 32 || self.nodes > 200_000 {
            return self.fail("JSON structural limit");
        }
        if self.i >= self.b.len() {
            return self.fail("Missing value");
        }
        match self.b[self.i] {
            b'"' => {
                self.string()?;
            }
            b'{' => {
                self.i += 1;
                self.ws();
                let mut keys = HashSet::new();
                if self.b.get(self.i) == Some(&b'}') {
                    self.i += 1;
                    return Ok(());
                }
                loop {
                    self.ws();
                    if self.b.get(self.i) != Some(&b'"') {
                        return self.fail("Expected key");
                    }
                    let key = self.string()?;
                    if matches!(key.as_str(), "__proto__" | "prototype" | "constructor")
                        || !keys.insert(key)
                    {
                        return self.fail("Duplicate/forbidden key");
                    }
                    self.ws();
                    if self.b.get(self.i) != Some(&b':') {
                        return self.fail("Expected colon");
                    }
                    self.i += 1;
                    self.value(depth + 1)?;
                    self.ws();
                    match self.b.get(self.i) {
                        Some(b'}') => {
                            self.i += 1;
                            break;
                        }
                        Some(b',') => self.i += 1,
                        _ => return self.fail("Expected object separator"),
                    }
                }
            }
            b'[' => {
                self.i += 1;
                self.ws();
                if self.b.get(self.i) == Some(&b']') {
                    self.i += 1;
                    return Ok(());
                }
                loop {
                    self.value(depth + 1)?;
                    self.ws();
                    match self.b.get(self.i) {
                        Some(b']') => {
                            self.i += 1;
                            break;
                        }
                        Some(b',') => self.i += 1,
                        _ => return self.fail("Expected array separator"),
                    }
                }
            }
            _ => {
                let start = self.i;
                while self.i < self.b.len()
                    && !matches!(
                        self.b[self.i],
                        b',' | b']' | b'}' | b' ' | b'\r' | b'\n' | b'\t'
                    )
                {
                    self.i += 1;
                }
                if self.i == start || self.i - start > 128 {
                    return self.fail("Invalid scalar");
                }
            }
        }
        Ok(())
    }
}
pub fn parse(bytes: &[u8], max: usize) -> Result<Value> {
    if bytes.len() > max {
        return Err(Error::new("JSON_SIZE", "JSON exceeds its byte budget"));
    }
    let mut s = Scan {
        b: bytes,
        i: 0,
        nodes: 0,
    };
    s.value(0)?;
    s.ws();
    if s.i != bytes.len() {
        return s.fail("Trailing JSON");
    }
    serde_json::from_slice(bytes)
        .map_err(|_| Error::new("JSON", "Invalid JSON value or unpaired Unicode surrogate"))
}
/// JavaScript receives exact decimal strings for ALL numeric RPC values.
pub fn for_ui(value: Value) -> Value {
    match value {
        Value::Number(n) => Value::String(n.to_string()),
        Value::Array(v) => Value::Array(v.into_iter().map(for_ui).collect()),
        Value::Object(m) => Value::Object(m.into_iter().map(|(k, v)| (k, for_ui(v))).collect()),
        other => other,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn duplicates() {
        assert!(parse(br#"{"a":1,"a":2}"#, 100).is_err());
        assert!(parse(br#"{"a":1,"\u0061":2}"#, 100).is_err());
    }
    #[test]
    fn structure() {
        assert!(parse(br#"{"__proto__":{}}"#, 100).is_err());
        assert!(parse(b"[", 100).is_err());
        assert!(parse(b"1 2", 100).is_err());
        assert!(parse(b"01", 100).is_err());
    }
    #[test]
    fn exact() {
        let v = parse(b"{\"n\":9007199254740993,\"m\":0.10000001}", 100).unwrap();
        assert_eq!(for_ui(v)["n"], "9007199254740993");
    }
    #[test]
    fn escaped() {
        assert!(parse(br#"{"x":"a\"b"}"#, 100).is_ok());
    }
}
