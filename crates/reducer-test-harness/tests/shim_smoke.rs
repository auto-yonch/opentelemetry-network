//! Plumbing proof for the C++ core shim.
//!
//! Not a behavior suite -- D2/D3 characterize the matching and logging cores.
//! These tests only establish that the seam works end to end: a Rust-encoded
//! message reaches a real C++ core, the virtual clock can be stepped by hand,
//! and what the core produces comes back as decodable bytes. If this file
//! fails, no core test built on the harness means anything.
//!
//! Compiled only when the shim is linked in (`cfg(otn_shim)`, set by
//! `build.rs` from `OTN_SHIM_LIB`), i.e. under the CMake `cargo-test` target.
#![cfg(otn_shim)]

use reducer_test_harness::decode;
use reducer_test_harness::encode::{self, TIMESTAMP_LEN};
use reducer_test_harness::shim::{Core, CoreKind, ShimError, TIMESLOT_DURATION_NS};

/// Fixed start of virtual time: 2017-07-14T02:40:00Z in nanoseconds, aligned to
/// a timeslot boundary so timeslot arithmetic in tests is exact.
const T0: u64 = 1_500_000_000_000_000_000;

fn matching_core() -> Core {
    Core::new(CoreKind::Matching, T0).expect("the matching core should be constructible")
}

#[test]
fn a_core_can_be_created_and_dropped() {
    let core = matching_core();
    assert_eq!(core.kind(), CoreKind::Matching);
    assert_eq!(core.last_error(), "");

    // Dropping runs otn_core_shim_destroy; a leak or double free shows up here
    // under the sanitizers CI runs.
    drop(core);

    let logging =
        Core::new(CoreKind::Logging, T0).expect("the logging core should be constructible");
    assert_eq!(logging.kind(), CoreKind::Logging);
}

#[test]
fn an_injected_message_is_consumed_by_the_core() {
    let mut core = matching_core();

    // Nothing queued yet, so a handling pass finds no work.
    assert_eq!(core.pump().expect("pump on an idle core"), 0);

    core.inject("ingest", encode::matching::pulse(T0))
        .expect("the ingest edge should accept a pulse");

    assert!(
        core.pump().expect("pump after injecting") >= 1,
        "the core should have read the injected message"
    );
}

#[test]
fn completing_a_timeslot_pulses_aggregation() {
    let mut core = matching_core();

    // A pulse in the first timeslot, then a clock advance past it: the core
    // completes the timeslot and pulses its downstream cores.
    core.inject("ingest", encode::matching::pulse(T0)).unwrap();
    core.pump().unwrap();

    assert!(
        core.drain("aggregation").unwrap().is_none(),
        "no timeslot has completed yet, so nothing should be downstream"
    );

    core.advance_clock(T0 + 2 * TIMESLOT_DURATION_NS)
        .expect("the clock should accept a later timestamp");

    let downstream = core.drain_all("aggregation").unwrap();
    assert!(
        !downstream.is_empty(),
        "completing a timeslot should have produced at least one message"
    );

    // Exact element sizes are D2/D3's business; here it is enough that what came
    // out is a message the aggregation decoder recognizes.
    let pulse = downstream
        .iter()
        .find(|element| decode::aggregation::pulse::decode(&element[TIMESTAMP_LEN..]).is_ok())
        .expect("aggregation should have received a pulse");

    assert!(pulse.len() >= TIMESTAMP_LEN + 2);
}

#[test]
fn an_unknown_edge_is_reported_not_ignored() {
    let mut core = matching_core();

    let injected = core.inject("aggregation", encode::matching::pulse(T0));
    assert!(
        matches!(injected, Err(ShimError::Invalid { ref detail }) if detail.contains("aggregation")),
        "injecting on a downstream edge should fail with a named error, got {injected:?}"
    );

    let drained = core.drain("ingest");
    assert!(
        matches!(drained, Err(ShimError::Invalid { ref detail }) if detail.contains("ingest")),
        "draining an upstream edge should fail with a named error, got {drained:?}"
    );
}

#[test]
fn out_of_order_timestamps_surface_the_cores_own_complaint() {
    let mut core = matching_core();

    core.inject("ingest", encode::matching::pulse(T0 + TIMESLOT_DURATION_NS))
        .unwrap();
    core.pump().unwrap();

    // Rewinding an edge is exactly the mistake a test author makes; the core
    // rejects it and the shim must not swallow the reason.
    core.inject("ingest", encode::matching::pulse(T0)).unwrap();
    let rewound = core.pump();

    assert!(
        matches!(rewound, Err(ShimError::Cpp { .. })),
        "a backwards timestamp should surface as a C++ error, got {rewound:?}"
    );
    assert!(
        !core.last_error().is_empty(),
        "the failure should carry the core's message"
    );
}
