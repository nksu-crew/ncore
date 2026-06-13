use std::ffi::c_void;
use std::sync::OnceLock;

use jni::objects::{JObject, JString};
use jni::sys::{JNI_VERSION_1_6, jboolean, jint, jlong};
use jni::{EnvUnowned, Outcome};
use log::{error, info};

use crate::ctl::{FmacCtl, FmacShm, KernelOp, invoke};
use crate::logging::setup_logging;
use crate::utils::jstring_to_string;

static SHM: OnceLock<FmacShm> = OnceLock::new();
static CTL: OnceLock<FmacCtl> = OnceLock::new();

macro_rules! jni_fn {
    (fn $name:ident($($arg:ident: $ty:ty),*) -> $ret:ty { $ctl:ident => $body:expr }) => {
        #[unsafe(no_mangle)]
        pub extern "system" fn $name(
            _env: EnvUnowned,
            _thiz: JObject,
            $($arg: $ty),*
        ) -> $ret {
            let Some($ctl) = get_ctl() else { return -1 };
            match $body {
                Ok(v) => v as $ret,
                Err(e) => {
                    error!("{}: {e}", stringify!($name));
                    -1
                }
            }
        }
    };
}

macro_rules! jni_fn_env {
    (fn $name:ident($($arg:ident: $ty:ty),*) -> $ret:ty { $env:ident, $ctl:ident => $body:expr }) => {
        #[unsafe(no_mangle)]
        pub extern "system" fn $name(
            mut env: EnvUnowned,
            _thiz: JObject,
            $($arg: $ty),*
        ) -> $ret {
            let Some($ctl) = get_ctl() else { return -1 };
            let outcome: Outcome<$ret, jni::errors::Error> = env.with_env(|$env| {
                match $body {
                    Ok(v) => Ok(v as $ret),
                    Err(e) => {
                        error!("{}: {e}", stringify!($name));
                        Ok(-1)
                    }
                }
            }).into_outcome();
            match outcome {
                Outcome::Ok(v) => v,
                _ => -1,
            }
        }
    };
}

fn get_ctl() -> Option<&'static FmacCtl> {
    CTL.get()
}

#[unsafe(no_mangle)]
pub extern "system" fn JNI_OnLoad(_vm: *mut jni::sys::JavaVM, _reserved: *mut c_void) -> jint {
    setup_logging();
    if let Err(e) = invoke(KernelOp::Authenticate) {
        error!("ctl authenticate: {e}");
    }
    info!("JNI_OnLoad completed");
    JNI_VERSION_1_6
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_me_nekosu_aqnya_ncore_ctl(
    _env: EnvUnowned,
    _thiz: JObject,
    value: jint,
) -> jint {
    let op = match value {
        1 => KernelOp::Authenticate,
        2 => KernelOp::GetRoot,
        3 => KernelOp::Ioctl,
        _ => return -1,
    };

    if let Err(e) = invoke(op) {
        error!("ctl({op:?}): {e}");
    }

    match value {
        1 => {
            if let Err(e) = FmacShm::from_proc().map(|shm| SHM.set(shm)) {
                error!("scan shm fd: {e:?}");
            }
        }
        3 => {
            if let Err(e) = FmacCtl::from_proc().map(|c| {
                info!("ctlfd acquired: {}", c.as_raw_fd());
                CTL.set(c)
            }) {
                error!("scan ctl fd: {e:?}");
            }
        }
        _ => {}
    }

    if SHM.get().is_none() { -1 } else { 0 }
}

jni_fn_env!(fn Java_me_nekosu_aqnya_ncore_setProfile(uid: jint, caps: jlong, domain_str: JString, namespace: jint) -> jint {
    env, ctl => {
        let domain = jstring_to_string(env, &domain_str);
        ctl.set_profile(uid as u32, caps as u64, &domain, namespace).map(|_| 0)
    }
});

jni_fn_env!(fn Java_me_nekosu_aqnya_ncore_addSelinuxRule(src: JString, tgt: JString, cls: JString, perm: JString, effect: jint, invert: jboolean) -> jint {
    env, ctl => {
        let src  = jstring_to_string(env, &src);
        let tgt  = jstring_to_string(env, &tgt);
        let cls  = jstring_to_string(env, &cls);
        let perm = jstring_to_string(env, &perm);
        ctl.add_selinux_rule(&src, &tgt, &cls, &perm, effect, invert).map(|_| 0)
    }
});

jni_fn!(fn Java_me_nekosu_aqnya_ncore_adduid(value: jint) -> jint {
    ctl => ctl.add_uid(value as u32).map(|_| 0)
});

jni_fn!(fn Java_me_nekosu_aqnya_ncore_deluid(value: jint) -> jint {
    ctl => ctl.del_uid(value as u32).map(|_| 0)
});

jni_fn!(fn Java_me_nekosu_aqnya_ncore_hasuid(value: jint) -> jint {
    ctl => ctl.has_uid(value as u32).map(|v| if v { 1 } else { 0 })
});

jni_fn!(fn Java_me_nekosu_aqnya_ncore_setCap(uid: jint, caps: jlong) -> jint {
    ctl => ctl.set_cap(uid as u32, caps as u64).map(|_| 0)
});

jni_fn!(fn Java_me_nekosu_aqnya_ncore_getCap(uid: jint) -> jlong {
    ctl => ctl.get_cap(uid as u32).map(|v| v as jlong)
});

jni_fn!(fn Java_me_nekosu_aqnya_ncore_delCap(uid: jint) -> jint {
    ctl => ctl.del_cap(uid as u32).map(|_| 0)
});

#[unsafe(no_mangle)]
pub extern "system" fn Java_me_nekosu_aqnya_ncore_addRule(
    _env: EnvUnowned,
    _thiz: JObject,
    _path: JString,
    _status_bits: jlong,
) -> jint {
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_me_nekosu_aqnya_ncore_delRule(
    _env: EnvUnowned,
    _thiz: JObject,
    _path: JString,
) -> jint {
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_me_nekosu_aqnya_ncore_helloLog(_env: EnvUnowned, _thiz: JObject) {
    log::debug!("Hello, this is a log from Rust!");
    info!("ncore build-as lib");
}
