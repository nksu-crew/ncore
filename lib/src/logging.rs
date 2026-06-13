#[cfg(target_os = "android")]
pub fn setup_logging() {
    android_logd_logger::builder()
        .parse_filters("debug")
        .tag("ncore")
        .prepend_module(false)
        .init();
}

#[cfg(not(target_os = "android"))]
pub fn setup_logging() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
}
