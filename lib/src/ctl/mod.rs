pub mod ioctl;

pub mod sys {
    #![allow(
        non_upper_case_globals,
        non_camel_case_types,
        non_snake_case,
        dead_code
    )]
    include!(concat!(env!("OUT_DIR"), "/fmac_bindings.rs"));
}

use std::os::fd::{AsFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::io::AsRawFd;

use rustix::event::{EventfdFlags, PollFd, PollFlags, eventfd};
use rustix::io::{Errno, read};
use rustix::time::Timespec;

use crate::error::{Error, Result};
use crate::utils::{scan_fd_by_link, write_str64};

use self::ioctl::*;
use self::sys::{fmac_sepolicy_rule, fmac_uid_cap, nksu_profile_data};

fn raw_ioctl<T>(fd: impl AsFd, cmd: u32, arg: *mut T) -> Result<()> {
    let ret = unsafe { libc::ioctl(fd.as_fd().as_raw_fd(), cmd as _, arg) };
    if ret < 0 {
        let errno = Errno::from_raw_os_error(unsafe { *libc::__errno() });
        Err(Error::Ioctl { cmd, errno })
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum KernelOp {
    Authenticate = 1,
    GetRoot = 2,
    Ioctl = 3,
}

pub fn invoke(op: KernelOp) -> Result<usize> {
    let nr = op as u32 + 200;
    let ret = unsafe { libc::prctl(nr as libc::c_int, 0, 0, 0, 0) };
    if ret < 0 {
        let errno = Errno::from_raw_os_error(unsafe { *libc::__errno() });
        Err(Error::Prctl { op: nr, errno })
    } else {
        Ok(ret as usize)
    }
}

pub struct FmacCtl(OwnedFd);

impl FmacCtl {
    pub fn from_proc() -> Result<Self> {
        scan_fd_by_link("[fmac_ctl]").map(|fd| unsafe { Self(OwnedFd::from_raw_fd(fd)) })
    }

    pub fn from_fd(fd: OwnedFd) -> Self {
        Self(fd)
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }

    pub fn add_uid(&self, uid: u32) -> Result<()> {
        let mut v = uid as i32;
        raw_ioctl(&self.0, IOC_ADD_UID, &mut v)
    }

    pub fn del_uid(&self, uid: u32) -> Result<()> {
        let mut v = uid as i32;
        raw_ioctl(&self.0, IOC_DEL_UID, &mut v)
    }

    pub fn has_uid(&self, uid: u32) -> Result<bool> {
        let mut v = uid as i32;
        raw_ioctl(&self.0, IOC_HAS_UID, &mut v)?;
        Ok(v != 0)
    }

    pub fn set_cap(&self, uid: u32, caps: u64) -> Result<()> {
        let mut uc = fmac_uid_cap {
            uid,
            caps,
            ..Default::default()
        };
        raw_ioctl(&self.0, IOC_SET_CAP, &mut uc)
    }

    pub fn get_cap(&self, uid: u32) -> Result<u64> {
        let mut uc = fmac_uid_cap {
            uid,
            caps: 0,
            ..Default::default()
        };
        raw_ioctl(&self.0, IOC_GET_CAP, &mut uc)?;
        Ok(uc.caps)
    }

    pub fn del_cap(&self, uid: u32) -> Result<()> {
        let mut uc = fmac_uid_cap {
            uid,
            caps: 0,
            ..Default::default()
        };
        raw_ioctl(&self.0, IOC_DEL_CAP, &mut uc)
    }

    pub fn set_profile(&self, uid: u32, caps: u64, domain: &str, namespace: i32) -> Result<()> {
        let mut p = nksu_profile_data {
            uid,
            caps,
            namespace,
            ..Default::default()
        };
        write_str64(&mut p.selinux_domain, domain);
        raw_ioctl(&self.0, IOC_SET_PROFILE, &mut p)
    }

    pub fn add_selinux_rule(
        &self,
        src: &str,
        tgt: &str,
        cls: &str,
        perm: &str,
        effect: i32,
        invert: bool,
    ) -> Result<()> {
        let mut r = fmac_sepolicy_rule {
            effect,
            invert: invert as _,
            ..Default::default()
        };
        write_str64(&mut r.src, src);
        write_str64(&mut r.tgt, tgt);
        write_str64(&mut r.cls, cls);
        write_str64(&mut r.perm, perm);
        raw_ioctl(&self.0, IOC_SEL_ADD_RULE, &mut r)
    }
}

pub struct FmacShm(OwnedFd);

impl FmacShm {
    pub fn from_proc() -> Result<Self> {
        scan_fd_by_link("[fmac_shm]").map(|fd| unsafe { Self(OwnedFd::from_raw_fd(fd)) })
    }

    pub fn from_fd(fd: OwnedFd) -> Self {
        Self(fd)
    }

    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

pub struct KernelEvent(OwnedFd);

impl KernelEvent {
    pub fn new() -> Result<Self> {
        eventfd(0, EventfdFlags::CLOEXEC)
            .map(Self)
            .map_err(Error::EventFd)
    }

    pub fn wait(&self) -> Result<u64> {
        loop {
            let mut pfd = [PollFd::new(&self.0, PollFlags::IN)];
            rustix::event::poll(&mut pfd, None).map_err(Error::Poll)?;

            let mut buf = [0u8; 8];
            match read(&self.0, &mut buf) {
                Ok(8) => return Ok(u64::from_ne_bytes(buf)),
                Ok(_) | Err(Errno::INTR) | Err(Errno::AGAIN) => continue,
                Err(e) => return Err(Error::Read(e)),
            }
        }
    }

    pub fn wait_timeout(&self, timeout_ms: i64) -> Result<Option<u64>> {
        let ts = Timespec {
            tv_sec: (timeout_ms / 1000) as _,
            tv_nsec: ((timeout_ms % 1000) * 1_000_000) as _,
        };
        let mut pfd = [PollFd::new(&self.0, PollFlags::IN)];
        match rustix::event::poll(&mut pfd, Some(&ts)) {
            Ok(0) | Err(Errno::INTR) => return Ok(None),
            Err(e) => return Err(Error::Poll(e)),
            Ok(_) => {}
        }

        let mut buf = [0u8; 8];
        match read(&self.0, &mut buf) {
            Ok(8) => Ok(Some(u64::from_ne_bytes(buf))),
            Ok(_) | Err(Errno::INTR) | Err(Errno::AGAIN) => Ok(None),
            Err(e) => Err(Error::Read(e)),
        }
    }

    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}
