use crate::ctl::sys::{fmac_sepolicy_rule, fmac_uid_cap, nksu_profile_data};

pub const FMAC_MAGIC: u32 = b'F' as u32;

macro_rules! _io {
    ($ty:expr, $nr:expr) => {
        (($ty) << 8) | ($nr)
    };
}
macro_rules! _iow {
    ($ty:expr, $nr:expr, $size:expr) => {
        (1u32 << 30) | (($size as u32) << 16) | (($ty as u32) << 8) | ($nr as u32)
    };
}
macro_rules! _ior {
    ($ty:expr, $nr:expr, $size:expr) => {
        (2u32 << 30) | (($size as u32) << 16) | (($ty as u32) << 8) | ($nr as u32)
    };
}
macro_rules! _iowr {
    ($ty:expr, $nr:expr, $size:expr) => {
        (3u32 << 30) | (($size as u32) << 16) | (($ty as u32) << 8) | ($nr as u32)
    };
}

pub const IOC_GET_SHM: u32 = _io!(FMAC_MAGIC, 0);
pub const IOC_BIND_EVT: u32 = _iow!(FMAC_MAGIC, 1, core::mem::size_of::<libc::c_int>());
pub const IOC_CHK_WRITE: u32 = _ior!(FMAC_MAGIC, 2, core::mem::size_of::<libc::c_int>());
pub const IOC_ADD_UID: u32 = _iow!(FMAC_MAGIC, 3, core::mem::size_of::<libc::c_int>());
pub const IOC_DEL_UID: u32 = _iow!(FMAC_MAGIC, 4, core::mem::size_of::<libc::c_int>());
pub const IOC_HAS_UID: u32 = _iowr!(FMAC_MAGIC, 5, core::mem::size_of::<libc::c_int>());
pub const IOC_SET_CAP: u32 = _iow!(FMAC_MAGIC, 6, core::mem::size_of::<fmac_uid_cap>());
pub const IOC_GET_CAP: u32 = _iowr!(FMAC_MAGIC, 7, core::mem::size_of::<fmac_uid_cap>());
pub const IOC_DEL_CAP: u32 = _iow!(FMAC_MAGIC, 8, core::mem::size_of::<fmac_uid_cap>());
pub const IOC_SEL_ADD_RULE: u32 = _iow!(FMAC_MAGIC, 9, core::mem::size_of::<fmac_sepolicy_rule>());
pub const IOC_SET_PROFILE: u32 = _iow!(FMAC_MAGIC, 10, core::mem::size_of::<nksu_profile_data>());
