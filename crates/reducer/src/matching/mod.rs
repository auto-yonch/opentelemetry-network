//! The Rust matching core: flow matching, enrichment, and the downstream
//! writes into the matching->aggregation and matching->logging queues.
//!
//! This is a port of `reducer/matching/` (chiefly `flow_span.cc`). Per the
//! spec's locked decision, the render-generated output is used for the wire
//! format only (`encoder`, `wire_messages`, `parsed_message`); the span state
//! the generated `Index` used to hold is hand-rolled in [`tables`], so the
//! 4.2M-element pool becomes a bounded hash table that grows with the traffic
//! actually seen.
//!
//! Layering, bottom up:
//!
//! ```text
//! lookup3 / ip / cgroup   pure helpers ported byte-for-byte from C++
//! tables                  bounded span pools, reference tables, UID keys
//! flow                    per-flow state, metric buffers, node resolution
//! output                  the write side over the Task 1 element-queue writer
//! state                   the state machine that ties them together
//! ```

pub mod cgroup;
pub mod flow;
pub mod ip;
pub mod lookup3;
pub mod output;
pub mod state;
pub mod tables;
