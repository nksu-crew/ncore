use std::ffi::CStr;
use std::os::raw::{c_char, c_int};
use std::sync::OnceLock;

use log::{error, info};

pub mod ctl;
pub mod error;
pub mod jni_api;
pub mod logging;
pub mod utils;

use crate::ctl::{FmacCtl, FmacShm, KernelOp, invoke};
use crate::logging::setup_logging;

static SHM: OnceLock<FmacShm> = OnceLock::new();
static CTL: OnceLock<FmacCtl> = OnceLock::new();

fn get_ctl() -> Option<&'static FmacCtl> {
    CTL.get()
}

/// Helper to convert C string to Rust string safely.
unsafe fn c_str_to_str<'a>(ptr: *const c_char) -> &'a str {
    if ptr.is_null() {
        return "";
    }
    unsafe { CStr::from_ptr(ptr) }.to_str().unwrap_or("")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ncore_init() -> c_int {
    setup_logging();
    if let Err(e) = invoke(KernelOp::Authenticate) {
        error!("ctl authenticate: {e}");
        return -1;
    }
    info!("ncore initialized via Flutter FFI");
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ncore_ctl(value: c_int) -> c_int {
    let op = match value {
        1 => KernelOp::Authenticate,
        2 => KernelOp::GetRoot,
        3 => KernelOp::Ioctl,
        _ => return -1,
    };

    if let Err(e) = invoke(op) {
        error!("ctl({op:?}): {e}");
        return -1;
    }

    match op {
        KernelOp::Authenticate => {
            if SHM.get().is_none() {
                match FmacShm::from_proc() {
                    Ok(shm) => {
                        let _ = SHM.set(shm);
                    }
                    Err(e) => error!("scan shm fd: {e}"),
                }
            }
        }
        KernelOp::Ioctl => {
            if CTL.get().is_none() {
                match FmacCtl::from_proc() {
                    Ok(c) => {
                        info!("ctlfd acquired: {}", c.as_raw_fd());
                        let _ = CTL.set(c);
                    }
                    Err(e) => error!("scan ctl fd: {e}"),
                }
            }
        }
        _ => {}
    }

    if op == KernelOp::Authenticate && SHM.get().is_none() {
        return -1;
    }
    if op == KernelOp::Ioctl && CTL.get().is_none() {
        return -1;
    }

    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ncore_set_profile(
    uid: c_int,
    caps: u64,
    domain: *const c_char,
    namespace: c_int,
) -> c_int {
    let Some(ctl) = get_ctl() else { return -1 };
    let domain_str = unsafe { c_str_to_str(domain) };
    match ctl.set_profile(uid as u32, caps, domain_str, namespace) {
        Ok(_) => 0,
        Err(e) => {
            error!("set_profile: {e}");
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ncore_add_selinux_rule(
    src: *const c_char,
    tgt: *const c_char,
    cls: *const c_char,
    perm: *const c_char,
    effect: c_int,
    invert: bool,
) -> c_int {
    let Some(ctl) = get_ctl() else { return -1 };
    let src_s = unsafe { c_str_to_str(src) };
    let tgt_s = unsafe { c_str_to_str(tgt) };
    let cls_s = unsafe { c_str_to_str(cls) };
    let perm_s = unsafe { c_str_to_str(perm) };
    match ctl.add_selinux_rule(src_s, tgt_s, cls_s, perm_s, effect, invert) {
        Ok(_) => 0,
        Err(e) => {
            error!("add_selinux_rule: {e}");
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ncore_adduid(uid: c_int) -> c_int {
    let Some(ctl) = get_ctl() else { return -1 };
    match ctl.add_uid(uid as u32) {
        Ok(_) => 0,
        Err(e) => {
            error!("adduid: {e}");
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ncore_deluid(uid: c_int) -> c_int {
    let Some(ctl) = get_ctl() else { return -1 };
    match ctl.del_uid(uid as u32) {
        Ok(_) => 0,
        Err(e) => {
            error!("deluid: {e}");
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ncore_hasuid(uid: c_int) -> c_int {
    let Some(ctl) = get_ctl() else { return -1 };
    match ctl.has_uid(uid as u32) {
        Ok(v) => {
            if v {
                1
            } else {
                0
            }
        }
        Err(e) => {
            error!("hasuid: {e}");
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ncore_set_cap(uid: c_int, caps: u64) -> c_int {
    let Some(ctl) = get_ctl() else { return -1 };
    match ctl.set_cap(uid as u32, caps) {
        Ok(_) => 0,
        Err(e) => {
            error!("set_cap: {e}");
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ncore_get_cap(uid: c_int) -> u64 {
    let Some(ctl) = get_ctl() else { return 0 };
    match ctl.get_cap(uid as u32) {
        Ok(v) => v,
        Err(e) => {
            error!("get_cap: {e}");
            0
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ncore_del_cap(uid: c_int) -> c_int {
    let Some(ctl) = get_ctl() else { return -1 };
    match ctl.del_cap(uid as u32) {
        Ok(_) => 0,
        Err(e) => {
            error!("del_cap: {e}");
            -1
        }
    }
}
