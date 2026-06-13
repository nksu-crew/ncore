use std::fs;
use std::os::unix::io::RawFd;
use std::path::Path;
use std::str::FromStr;

use jni::Env;
use jni::objects::JString;

use crate::error::{Error, Result};

pub fn write_str64(dst: &mut [::std::os::raw::c_char; 64], s: &str) {
    for b in dst.iter_mut() {
        *b = 0;
    }
    for (d, byte) in dst.iter_mut().zip(s.bytes()) {
        *d = byte as _;
    }
}

pub fn scan_fd_by_link(target: &'static str) -> Result<RawFd> {
    let dir = Path::new("/proc/self/fd");
    let entries = fs::read_dir(dir).map_err(|_| Error::FdNotFound(target))?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        let Ok(n) = RawFd::from_str(name_str) else {
            continue;
        };
        let Ok(dest) = fs::read_link(dir.join(&name)) else {
            continue;
        };
        if dest.to_str().map_or(false, |s| s.contains(target)) {
            return Ok(n);
        }
    }
    Err(Error::FdNotFound(target))
}

pub fn jstring_to_string(env: &mut Env<'_>, s: &JString<'_>) -> String {
    if s.is_null() {
        return String::new();
    }
    // Using deprecated get_string for now as suggested replacement was ambiguous in this version
    #[allow(deprecated)]
    env.get_string(s).map(|js| js.into()).unwrap_or_default()
}
