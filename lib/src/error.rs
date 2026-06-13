use rustix::io::Errno;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("ioctl({cmd:#010x}): {errno}")]
    Ioctl { cmd: u32, errno: Errno },
    #[error("prctl(op={op}): errno={errno}")]
    Prctl { op: u32, errno: i32 },
    #[error("fd not found: '{0}'")]
    FdNotFound(&'static str),
    #[error("eventfd: {0}")]
    EventFd(Errno),
    #[error("poll: {0}")]
    Poll(Errno),
    #[error("read eventfd: {0}")]
    Read(Errno),
}

pub type Result<T> = std::result::Result<T, Error>;
