extern crate log;
use jni::sys::jint;
use log::info;

#[cfg(target_os = "android")]
fn setup_logging() {
    android_logd_logger::builder().parse_filters("debug").init();
}

#[cfg(not(target_os = "android"))]
fn setup_logging() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
}

#[unsafe(no_mangle)]
pub extern "system" fn JNI_OnLoad(_vm: jni::sys::JavaVM, _reserved: *mut std::ffi::c_void) -> jint {
    setup_logging();
    info!("JNI_OnLoad completed");
    jni::sys::JNI_VERSION_1_6
}
