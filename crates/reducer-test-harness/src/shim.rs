//! Safe Rust wrapper over the test-only C++ core shim (`reducer/test/core_shim.h`).
//!
//! Available only when the shim is on the link line, which is the case for the
//! CMake `cargo-test` target (it sets `OTN_SHIM_LIB`; see `build.rs`).
//!
//! A [`Core`] is a real C++ core instance wired to real `RpcQueueMatrix` edges,
//! stepped by hand instead of by a libuv timer, so a test is a sequence of
//! inject / pump / advance_clock / drain with no threads and no wall clock.

use core::ffi::{c_char, CStr};
use std::ffi::CString;
use std::fmt;

// Forces the `reducer` crate into the test binary. Nothing in Rust calls it, but
// the C++ libraries behind the shim reference the Rust side of the reducer's cxx
// bridges (aggregation core, entrypoint, OTLP publisher), and an unreferenced
// crate is not linked -- the symbols would resolve nowhere.
use reducer as _;

/// Timeslot length of a core's virtual clock, in nanoseconds. The clock divides
/// timestamps by 1e9 (`VirtualClock`'s default divider), so a timeslot is one
/// second of virtual time.
pub const TIMESLOT_DURATION_NS: u64 = 1_000_000_000;

/// Largest message the drain buffer accommodates. The wire format's length
/// field is a `u16`, so no element can exceed this.
const DRAIN_BUF_LEN: usize = u16::MAX as usize + 16;

const OK: i64 = 0;
const ERR_INVALID: i64 = -1;
const ERR_EMPTY: i64 = -2;
const ERR_NOSPACE: i64 = -3;
const ERR_EXCEPTION: i64 = -4;

mod ffi {
    use core::ffi::c_char;

    #[repr(C)]
    pub struct otn_core_shim {
        _opaque: [u8; 0],
    }

    extern "C" {
        pub fn otn_core_shim_create(
            core: *const c_char,
            initial_timestamp: u64,
        ) -> *mut otn_core_shim;
        pub fn otn_core_shim_destroy(shim: *mut otn_core_shim);
        pub fn otn_core_shim_inject(
            shim: *mut otn_core_shim,
            edge: *const c_char,
            data: *const u8,
            len: usize,
        ) -> i64;
        pub fn otn_core_shim_pump(shim: *mut otn_core_shim) -> i64;
        pub fn otn_core_shim_advance_clock(shim: *mut otn_core_shim, timestamp: u64) -> i64;
        pub fn otn_core_shim_drain(
            shim: *mut otn_core_shim,
            edge: *const c_char,
            out: *mut u8,
            cap: usize,
        ) -> i64;
        pub fn otn_core_shim_last_error(shim: *const otn_core_shim) -> *const c_char;
    }
}

/// Which C++ core to instantiate.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CoreKind {
    Matching,
    Logging,
}

impl CoreKind {
    fn as_str(self) -> &'static str {
        match self {
            CoreKind::Matching => "matching",
            CoreKind::Logging => "logging",
        }
    }
}

impl fmt::Display for CoreKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Everything that can go wrong on the far side of the ABI. `detail` carries
/// the shim's message -- for a [`ShimError::Cpp`] that is the C++ exception's
/// `what()`, which is how a core reports rejected input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShimError {
    /// The core could not be constructed.
    Create { kind: CoreKind },
    /// An argument was rejected: unknown edge, or a name containing a NUL.
    Invalid { detail: String },
    /// The drain buffer was too small for the pending message.
    NoSpace { detail: String },
    /// A C++ exception escaped the core.
    Cpp { detail: String },
    /// The ABI returned a code this wrapper does not know.
    UnknownCode { code: i64, detail: String },
}

impl fmt::Display for ShimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShimError::Create { kind } => write!(f, "failed to create the {kind} core"),
            ShimError::Invalid { detail } => write!(f, "invalid argument: {detail}"),
            ShimError::NoSpace { detail } => write!(f, "buffer too small: {detail}"),
            ShimError::Cpp { detail } => write!(f, "C++ exception: {detail}"),
            ShimError::UnknownCode { code, detail } => {
                write!(f, "unexpected shim return code {code}: {detail}")
            }
        }
    }
}

impl std::error::Error for ShimError {}

/// A C++ core instance plus the queues around it.
///
/// Not `Send`: the C++ core keeps thread-local state, so it must be created and
/// driven on one thread. The raw handle makes that a compile-time property.
pub struct Core {
    handle: *mut ffi::otn_core_shim,
    kind: CoreKind,
}

impl Core {
    /// Creates a core seeded with `initial_timestamp` (nanoseconds). Use a fixed
    /// timestamp: the core's behavior depends on it, and tests pin exact values.
    pub fn new(kind: CoreKind, initial_timestamp: u64) -> Result<Self, ShimError> {
        let name = CString::new(kind.as_str()).expect("core names contain no NUL");

        // SAFETY: `name` is a valid NUL-terminated string that outlives the call.
        let handle = unsafe { ffi::otn_core_shim_create(name.as_ptr(), initial_timestamp) };

        if handle.is_null() {
            return Err(ShimError::Create { kind });
        }

        Ok(Self { handle, kind })
    }

    pub fn kind(&self) -> CoreKind {
        self.kind
    }

    /// Enqueues one encoded message on an upstream edge, named after the sending
    /// app ("ingest", "matching", "aggregation").
    ///
    /// Timestamps on one edge must not go backwards; the core rejects
    /// out-of-order input with [`ShimError::Cpp`].
    pub fn inject(&mut self, edge: &str, message: impl AsRef<[u8]>) -> Result<(), ShimError> {
        let message = message.as_ref();
        let edge_c = self.edge_name(edge)?;

        // SAFETY: handle is non-null for the lifetime of self; `message` is a
        // live slice for the duration of the call, which only reads from it.
        let code = unsafe {
            ffi::otn_core_shim_inject(
                self.handle,
                edge_c.as_ptr(),
                message.as_ptr(),
                message.len(),
            )
        };

        self.check(code).map(|_| ())
    }

    /// Runs the core's RPC handling until the core goes quiet. Returns the
    /// number of handling passes that consumed at least one message.
    ///
    /// A fresh core needs one pass to seed its virtual clock before it will
    /// handle anything, so "quiet" means two idle passes in a row; the count
    /// this returns is of passes that did work, not of passes run.
    pub fn pump(&mut self) -> Result<u64, ShimError> {
        // SAFETY: handle is non-null for the lifetime of self.
        let code = unsafe { ffi::otn_core_shim_pump(self.handle) };

        self.check(code).map(|passes| passes as u64)
    }

    /// Declares that every upstream edge reached `timestamp` and runs the core
    /// to quiescence, which completes the timeslot if the clock advances.
    ///
    /// Pump pending input first: advancing past queued messages makes them
    /// out-of-order.
    pub fn advance_clock(&mut self, timestamp: u64) -> Result<(), ShimError> {
        // SAFETY: handle is non-null for the lifetime of self.
        let code = unsafe { ffi::otn_core_shim_advance_clock(self.handle, timestamp) };

        self.check(code).map(|_| ())
    }

    /// Takes the next message the core produced on a downstream edge, named
    /// after the receiving app. `Ok(None)` means the edge is empty.
    ///
    /// The bytes are a queue element: 8-byte timestamp, then the wire message.
    pub fn drain(&mut self, edge: &str) -> Result<Option<Vec<u8>>, ShimError> {
        let edge_c = self.edge_name(edge)?;
        let mut buf = vec![0u8; DRAIN_BUF_LEN];

        // SAFETY: handle is non-null for the lifetime of self; `buf` is a live
        // allocation of exactly the capacity passed in.
        let code = unsafe {
            ffi::otn_core_shim_drain(self.handle, edge_c.as_ptr(), buf.as_mut_ptr(), buf.len())
        };

        if code == ERR_EMPTY {
            return Ok(None);
        }

        let len = self.check(code)? as usize;
        buf.truncate(len);

        Ok(Some(buf))
    }

    /// Drains an edge until it is empty, preserving order.
    pub fn drain_all(&mut self, edge: &str) -> Result<Vec<Vec<u8>>, ShimError> {
        let mut messages = Vec::new();

        while let Some(message) = self.drain(edge)? {
            messages.push(message);
        }

        Ok(messages)
    }

    /// The shim's description of the last failure. Empty when the last call
    /// succeeded.
    pub fn last_error(&self) -> String {
        // SAFETY: handle is non-null for the lifetime of self; the returned
        // pointer is a NUL-terminated string owned by the shim, valid until the
        // next call on it, and copied here before returning.
        let raw = unsafe { ffi::otn_core_shim_last_error(self.handle) };

        if raw.is_null() {
            return String::new();
        }

        // SAFETY: as above -- non-null, NUL-terminated, owned by the shim.
        unsafe { CStr::from_ptr(raw as *const c_char) }
            .to_string_lossy()
            .into_owned()
    }

    fn edge_name(&self, edge: &str) -> Result<CString, ShimError> {
        CString::new(edge).map_err(|_| ShimError::Invalid {
            detail: format!("edge name {edge:?} contains a NUL byte"),
        })
    }

    /// Turns a negative ABI code into a typed error, attaching the shim's
    /// message. Callers that treat a specific code as a non-error (drain and
    /// `ERR_EMPTY`) handle it before calling this.
    fn check(&self, code: i64) -> Result<i64, ShimError> {
        if code >= OK {
            return Ok(code);
        }

        let detail = self.last_error();

        Err(match code {
            ERR_INVALID => ShimError::Invalid { detail },
            ERR_NOSPACE => ShimError::NoSpace { detail },
            ERR_EXCEPTION => ShimError::Cpp { detail },
            ERR_EMPTY => ShimError::Invalid {
                detail: format!("edge reported empty where a value was required: {detail}"),
            },
            code => ShimError::UnknownCode { code, detail },
        })
    }
}

impl Drop for Core {
    fn drop(&mut self) {
        // SAFETY: handle came from otn_core_shim_create, is destroyed once, and
        // is not used again.
        unsafe { ffi::otn_core_shim_destroy(self.handle) };
    }
}

impl fmt::Debug for Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Core").field("kind", &self.kind).finish()
    }
}
