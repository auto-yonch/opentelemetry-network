/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

// Test-only C ABI over the still-C++ reducer cores.
//
// This shim exists so that Rust test bodies can drive a real core instance --
// wired to real RpcQueueMatrix edges -- without a live network, a libuv loop or
// a thread. It is built as a static library by a test-only CMake target and
// linked into the `cargo test` binary; it is never part of a shipped artifact.
//
// The shim deliberately has NO message-encoding helpers: tests encode wire
// bytes in Rust with the render-generated encoder crates and hand them here as
// opaque buffers.
//
// When a core is ported to Rust, its shim entry is deleted and the same tests
// re-point at the native implementation.

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handle to a core instance plus the queues around it.
typedef struct otn_core_shim otn_core_shim;

// Return codes. Non-negative values are successful results (byte or message
// counts); negative values are errors.
#define OTN_SHIM_OK 0
// An argument was rejected: unknown core name, unknown edge name, null buffer.
#define OTN_SHIM_ERR_INVALID (-1)
// Nothing available to drain on this edge.
#define OTN_SHIM_ERR_EMPTY (-2)
// The caller's buffer is too small for the next message.
#define OTN_SHIM_ERR_NOSPACE (-3)
// A C++ exception escaped; see otn_core_shim_last_error().
#define OTN_SHIM_ERR_EXCEPTION (-4)

// Creates a core instance of the given kind.
//
// `core` is one of: "matching", "logging".
// `initial_timestamp` seeds the core's clock, in nanoseconds; tests should use
// a fixed value so behavior is reproducible.
//
// The core is created with its connection flagged as authenticated, matching
// how the reducer wires up in-process cores.
//
// Returns NULL on failure.
otn_core_shim *otn_core_shim_create(char const *core, uint64_t initial_timestamp);

// Destroys a core instance created by otn_core_shim_create(). NULL is a no-op.
void otn_core_shim_destroy(otn_core_shim *shim);

// Writes one already-encoded message onto an upstream edge of this core.
//
// `edge` names the sending app, e.g. "ingest" for the matching core.
// `data`/`len` are the encoded element: an 8-byte native-endian timestamp
// followed by the wire message, exactly as the render-generated Rust encoders
// produce it.
//
// Messages on one edge must have non-decreasing timestamps; the core throws on
// out-of-order input (surfaced as OTN_SHIM_ERR_EXCEPTION).
//
// Injecting only enqueues. Call otn_core_shim_pump() to have the core read it.
//
// Returns OTN_SHIM_OK, or a negative error code.
int64_t otn_core_shim_inject(otn_core_shim *shim, char const *edge, uint8_t const *data, size_t len);

// Runs the core's RPC handling loop until it stops making progress.
//
// This is the same code path the core's libuv RPC timer drives in production
// (Core::handle_rpc), called directly so tests are deterministic.
//
// Returns the number of handling passes that consumed at least one message, or
// a negative error code.
int64_t otn_core_shim_pump(otn_core_shim *shim);

// Declares that every upstream edge has reached `timestamp`, then runs one
// handling pass -- which completes the current timeslot if the virtual clock
// advances.
//
// Use this only once pending input has been pumped: telling the clock that an
// edge reached a later timestamp while messages with earlier timestamps are
// still queued makes those messages out-of-order.
//
// Returns OTN_SHIM_OK, or a negative error code.
int64_t otn_core_shim_advance_clock(otn_core_shim *shim, uint64_t timestamp);

// Copies the next message the core produced on a downstream edge into `out`.
//
// `edge` names the receiving app, e.g. "aggregation" for the matching core.
// The copied bytes have the same shape as inject()'s input: 8-byte timestamp
// followed by the wire message.
//
// Returns the number of bytes copied, OTN_SHIM_ERR_EMPTY when the edge has no
// pending message, OTN_SHIM_ERR_NOSPACE when `cap` is too small (the message
// stays queued), or another negative error code.
int64_t otn_core_shim_drain(otn_core_shim *shim, char const *edge, uint8_t *out, size_t cap);

// Description of the most recent failure on this shim instance, or an empty
// string. Owned by the shim; valid until the next call on it.
char const *otn_core_shim_last_error(otn_core_shim const *shim);

#ifdef __cplusplus
} // extern "C"
#endif
