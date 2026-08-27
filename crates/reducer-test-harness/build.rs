include!("../build/otn_link_build.rs");

fn main() {
    println!("cargo:rerun-if-env-changed=OTN_SHIM_LIB");
    println!("cargo:rustc-check-cfg=cfg(otn_shim)");

    // The C++ side of the harness only exists when CMake drives the build: the
    // `cargo-test` target compiles the shim, exports the reducer link line, and
    // sets OTN_SHIM_LIB. A bare `cargo test` still builds this crate -- the
    // encoders and their unit tests -- with the FFI half compiled out, so the
    // workspace stays usable without a configured CMake tree.
    if std::env::var_os("OTN_SHIM_LIB").is_some() {
        println!("cargo:rustc-cfg=otn_shim");
    }

    run();
}
