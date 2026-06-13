use std::mem::MaybeUninit;
use std::os::fd::RawFd;

use jni::Env;
use jni::objects::JString;
use rustix::fs::{RawDir, readlinkat};

use crate::error::{Error, Result};

pub fn write_str64(dst: &mut [u8; 64], s: &str) {
    dst.fill(0);
    for (d, byte) in dst.iter_mut().zip(s.bytes().take(63)) {
        *d = byte;
    }
}

pub fn scan_fd_by_link(target: &str) -> Result<RawFd> {
    let fd_dir = rustix::fs::openat(
        rustix::fs::CWD,
        "/proc/self/fd",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| Error::FdNotFound(target.to_string()))?;

    let mut buf = [MaybeUninit::<u8>::uninit(); 4096];
    let mut iter = RawDir::new(&fd_dir, &mut buf);

    while let Some(entry) = iter.next() {
        let entry = entry.map_err(|_| Error::FdNotFound(target.to_string()))?;
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }

        let mut link_buf = [0u8; 128];
        if let Ok(dest) = readlinkat(&fd_dir, name, &mut link_buf) {
            if dest
                .as_bytes()
                .windows(target.len())
                .any(|w| w == target.as_bytes())
            {
                if let Ok(fd_str) = std::str::from_utf8(name.to_bytes()) {
                    if let Ok(fd) = fd_str.parse::<RawFd>() {
                        return Ok(fd);
                    }
                }
            }
        }
    }

    Err(Error::FdNotFound(target.to_string()))
}

pub fn jstring_to_string(env: &mut Env<'_>, s: &JString<'_>) -> String {
    if s.is_null() {
        return String::new();
    }
    #[allow(deprecated)]
    env.get_string(s).map(|js| js.into()).unwrap_or_else(|e| {
        log::error!("failed to get jstring: {e}");
        String::new()
    })
}
