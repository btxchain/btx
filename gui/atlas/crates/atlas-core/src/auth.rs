use crate::{Error, Result};
use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;
/// The path is selected in a native dialog; credentials never cross the WebView IPC.
#[derive(Clone)]
pub struct CookieSource {
    path: PathBuf,
}
impl CookieSource {
    pub fn new(path: PathBuf) -> Result<Self> {
        let c = Self { path };
        let _ = c.load()?;
        Ok(c)
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn load(&self) -> Result<Zeroizing<String>> {
        let meta = fs::symlink_metadata(&self.path)
            .map_err(|_| Error::new("COOKIE", "Cannot read selected authentication cookie"))?;
        if meta.file_type().is_symlink() || !meta.is_file() || meta.len() > 4096 {
            return Err(Error::new(
                "COOKIE",
                "Cookie must be a regular file, not a symlink, at most 4096 bytes",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o077 != 0 {
                return Err(Error::new(
                    "COOKIE_PERMISSIONS",
                    "Cookie must not be accessible to group or other users",
                ));
            }
        }
        let file = File::open(&self.path)
            .map_err(|_| Error::new("COOKIE", "Cannot open authentication cookie"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let opened = file
                .metadata()
                .map_err(|_| Error::new("COOKIE", "Cookie metadata unavailable"))?;
            if opened.dev() != meta.dev() || opened.ino() != meta.ino() {
                return Err(Error::new("COOKIE_CHANGED", "Cookie changed while opening"));
            }
        }
        let mut bytes = Zeroizing::new(Vec::new());
        file.take(4097)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::new("COOKIE", "Cookie read failed"))?;
        if bytes.len() > 4096 {
            return Err(Error::new("COOKIE", "Cookie too large"));
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| Error::new("COOKIE", "Cookie is not UTF-8"))?
            .trim_end_matches(['\r', '\n']);
        if !text.contains(':') || text.len() < 3 || text.bytes().any(|b| b < 32 || b == 127) {
            return Err(Error::new("COOKIE", "Malformed authentication cookie"));
        }
        Ok(Zeroizing::new(text.to_owned()))
    }
}
