use rustix::io::Errno;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("ioctl({cmd:#010x}): {errno}")]
    Ioctl { cmd: u32, errno: Errno },
    #[error("prctl(op={op}): {errno}")]
    Prctl { op: u32, errno: Errno },
    #[error("fd not found for target: '{0}'")]
    FdNotFound(String),
    #[error("eventfd error: {0}")]
    EventFd(Errno),
    #[error("poll error: {0}")]
    Poll(Errno),
    #[error("read error: {0}")]
    Read(Errno),
}

pub type Result<T> = std::result::Result<T, Error>;
