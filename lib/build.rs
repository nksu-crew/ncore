fn main() {
    let bindings = bindgen::Builder::default()
        .header("src/ioctl.h")
        // 只生成需要的类型
        .allowlist_type("nksu_profile_data")
        .allowlist_type("fmac_sepolicy_rule")
        .allowlist_type("fmac_uid_cap")
        // 保持 #define 常量（ioctl 宏展开后是整数）
        .allowlist_var("IOC_.*")
        // arm64 目标
        .clang_arg("--target=aarch64-linux-android")
        // linux/ioctl.h 需要这个
        .clang_arg("-D__KERNEL__")
        .clang_arg(format!(
            "-I{}",
            std::env::var("ANDROID_NDK_SYSROOT").unwrap_or_else(|_| "/usr/include".into())
        ))
        .derive_debug(true)
        .derive_default(true)
        // 确保布局测试生成
        .layout_tests(true)
        .generate()
        .expect("bindgen failed");

    bindings
        .write_to_file(
            std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("fmac_bindings.rs"),
        )
        .expect("write failed");

    println!("cargo:rerun-if-changed=src/fmac.h");
}
