//! Test harness for the reducer cores that are still C++.
//!
//! Two halves:
//!
//! - [`encode`]: typed builders over the render-generated encoders, so a test
//!   writes `encode::matching::flow_start(t, ...)` instead of hand-computing an
//!   exact buffer length for a raw extern-"C" function.
//! - [`shim`]: a safe wrapper over the test-only C++ shim
//!   (`reducer/test/core_shim.h`) -- create a core, inject bytes on an edge,
//!   pump, advance the virtual clock, drain what came out.
//!
//! ```text
//!   Rust test  --encode-->  bytes  --inject-->  [ C++ core ]  --drain-->  bytes  --decode-->  assertions
//! ```
//!
//! Everything here is test-only and never linked into a shipped binary.
//!
//! # Running
//!
//! The C++ half needs CMake, which builds the shim and hands cargo the reducer
//! link line:
//!
//! ```sh
//! make cargo-test     # or: cmake --build <build-dir> --target cargo-test
//! ```
//!
//! A plain `cargo test` still builds this crate and runs the [`encode`] unit
//! tests; [`shim`] is compiled out (`cfg(otn_shim)`) because its symbols would
//! not resolve, and tests that drive a core are skipped with it.
//!
//! # Why a shim at all
//!
//! The cores derive from `CoreBase`, own their libuv loop and thread, and are
//! only reachable in-process. The shim exposes the four operations a
//! characterization test needs, over a C ABI, so the test bodies can live in
//! Rust today and survive each core's port tomorrow: when a core becomes Rust,
//! its shim entry is deleted and the same tests point at the native type.

pub mod encode;

#[cfg(otn_shim)]
pub mod shim;

/// Re-exported decoders for the messages cores emit, so tests assert on parsed
/// values instead of raw bytes.
pub mod decode {
    pub use encoder_ebpf_net_aggregation::parsed_message as aggregation;
    pub use encoder_ebpf_net_ingest::parsed_message as ingest;
    pub use encoder_ebpf_net_logging::parsed_message as logging;
    pub use encoder_ebpf_net_matching::parsed_message as matching;
}
