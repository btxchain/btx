use crate::{hash, strict_json, Error, Result};
use serde_json::{json, Value};
use std::{
    fs,
    io::{Read, Write},
    path::Path,
};
/// The file name a save dialog may suggest: a plain name with an extension, no directory parts.
pub fn suggested_name(name: &str) -> Option<String> {
    let ok = (3..=64).contains(&name.len())
        && !name.starts_with('.')
        && !name.ends_with('.')
        && name.contains('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
    ok.then(|| name.to_owned())
}
pub fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>> {
    let m =
        fs::symlink_metadata(path).map_err(|_| Error::new("FILE", "File metadata unavailable"))?;
    if !m.is_file() || m.file_type().is_symlink() || m.len() > max as u64 {
        return Err(Error::new(
            "FILE",
            "Selected file must be regular, non-symlink and within the byte budget",
        ));
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .and_then(|f| f.take(max as u64 + 1).read_to_end(&mut bytes))
        .map_err(|_| Error::new("FILE", "File read failed"))?;
    if bytes.len() > max {
        return Err(Error::new(
            "FILE_SIZE",
            "File changed beyond its byte budget",
        ));
    }
    Ok(bytes)
}
pub fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    if bytes.len() > strict_json::MAX_RESPONSE {
        return Err(Error::new("EXPORT_SIZE", "Export exceeds 4 MiB"));
    }
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|_| {
        Error::new(
            "EXPORT",
            "Destination exists or cannot be created; choose a new filename",
        )
    })?;
    f.write_all(bytes)
        .and_then(|_| f.sync_all())
        .map_err(|_| Error::new("EXPORT", "Export write failed"))
}
pub fn qr_matrix(text: &str) -> Result<Value> {
    if text.is_empty() || text.len() > 2048 {
        return Err(Error::new("QR", "QR text exceeds budget"));
    }
    let code = qrcode::QrCode::new(text.as_bytes())
        .map_err(|_| Error::new("QR", "Content cannot fit a QR code"))?;
    let width = code.width();
    let cells = code
        .to_colors()
        .iter()
        .map(|c| *c == qrcode::Color::Dark)
        .collect::<Vec<_>>();
    Ok(json!({"width":width,"cells":cells}))
}
pub fn inspect_safetensors(path: &Path) -> Result<Value> {
    // Only the bounded metadata header is read. Tensor bytes are not loaded or executed.
    let meta =
        fs::symlink_metadata(path).map_err(|_| Error::new("TENSORS", "Cannot inspect model"))?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(Error::new("TENSORS", "Select a regular SafeTensors file"));
    }
    let mut f = fs::File::open(path).map_err(|_| Error::new("TENSORS", "Cannot open model"))?;
    let mut prefix = [0u8; 8];
    f.read_exact(&mut prefix)
        .map_err(|_| Error::new("TENSORS", "Missing SafeTensors header"))?;
    let len = u64::from_le_bytes(prefix);
    if len == 0 || len > 1048576 || len.saturating_add(8) > meta.len() {
        return Err(Error::new(
            "TENSORS",
            "Invalid or oversized SafeTensors header",
        ));
    }
    let mut bytes = vec![0; len as usize];
    f.read_exact(&mut bytes)
        .map_err(|_| Error::new("TENSORS", "Incomplete header"))?;
    let value = strict_json::parse(&bytes, 1048576)?;
    let obj = value
        .as_object()
        .ok_or_else(|| Error::new("TENSORS", "Header must be an object"))?;
    let mut tensors = Vec::new();
    for (name, v) in obj {
        if name == "__metadata__" {
            continue;
        }
        if tensors.len() >= 4096 {
            return Err(Error::new(
                "TENSORS",
                "Too many tensors for this inspection",
            ));
        }
        let offsets = v
            .get("data_offsets")
            .and_then(Value::as_array)
            .ok_or_else(|| Error::new("TENSORS", "Missing tensor offsets"))?;
        if offsets.len() != 2 {
            return Err(Error::new("TENSORS", "Invalid tensor offsets"));
        }
        let a = offsets[0]
            .as_u64()
            .ok_or_else(|| Error::new("TENSORS", "Invalid offset"))?;
        let b = offsets[1]
            .as_u64()
            .ok_or_else(|| Error::new("TENSORS", "Invalid offset"))?;
        if a > b || b > meta.len() - len - 8 {
            return Err(Error::new("TENSORS", "Tensor lies outside the file"));
        }
        let shape = v
            .get("shape")
            .and_then(Value::as_array)
            .ok_or_else(|| Error::new("TENSORS", "Missing shape"))?;
        if shape.len() > 16 || shape.iter().any(|d| d.as_u64().is_none()) {
            return Err(Error::new("TENSORS", "Invalid tensor shape"));
        }
        tensors.push(
            json!({"name":name,"dtype":v.get("dtype"),"shape":shape,"bytes":(b-a).to_string()}),
        );
    }
    Ok(
        json!({"schema":"btx.atlas.tensor-header/1","header_sha256":hash(&bytes),"file_bytes":meta.len().to_string(),"tensors":tensors,"weights_verified":false,"activation_capture":false,"note":"Header-only inspection, not full SafeTensors validation or model qualification"}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_suggested_name_is_a_plain_file_name_with_an_extension() {
        assert_eq!(
            suggested_name("wallet-history.csv").as_deref(),
            Some("wallet-history.csv")
        );
        assert_eq!(
            suggested_name("transaction.psbt").as_deref(),
            Some("transaction.psbt")
        );
        for bad in [
            "",
            "Untitled",
            ".csv",
            "history.",
            "../x.csv",
            "a/b.csv",
            "a b.csv",
            "x.c\u{301}sv",
        ] {
            assert!(suggested_name(bad).is_none(), "{bad}");
        }
        assert!(suggested_name(&format!("{}.csv", "a".repeat(61))).is_none());
    }
}
