//! The matching core's write side: matching->aggregation and
//! matching->logging.
//!
//! Every message goes out through the Task 1 [`EqWriter`] driving the
//! render-generated encoders, so the bytes on the queue are the same bytes the
//! C++ writers produce. This module owns the sizing (the generated
//! `*_WIRE_SIZE` constants plus dynamic payload lengths) and the blob
//! plumbing; nothing above it touches a raw pointer.
//!
//! Writes are fallible — a full queue or an oversized message returns
//! [`EqError`] rather than being dropped silently. Callers surface the failure
//! through [`WriteStats`], which the core exposes.

use std::os::raw::c_char;
use std::sync::atomic::{AtomicU64, Ordering};

use element_queue::{EqError, EqWriter, MessageSize};

use encoder_ebpf_net_aggregation::encoder as agg_enc;
use encoder_ebpf_net_aggregation::wire_messages as agg_wire;
use encoder_ebpf_net_aggregation::JbBlob as AggBlob;
use encoder_ebpf_net_logging::encoder as log_enc;
use encoder_ebpf_net_logging::wire_messages as log_wire;

use super::flow::{DnsMetrics, HttpMetrics, NodeData, TcpMetrics, UdpMetrics};

/// Borrowed string as the generated encoders take it.
///
/// The pointer is only read during the encoder call, which happens inside the
/// closure the writer invokes, so borrowing the caller's string is sound.
fn blob(s: &str) -> AggBlob {
    AggBlob {
        buf: s.as_ptr() as *const c_char,
        len: s.len() as u16,
    }
}

/// Counters describing what the write side did, including what it could not
/// do. Shared so a supervisor can read them while the core runs.
#[derive(Debug, Default)]
pub struct WriteStats {
    messages_written: AtomicU64,
    write_errors: AtomicU64,
}

impl WriteStats {
    /// Messages successfully published downstream.
    pub fn messages_written(&self) -> u64 {
        self.messages_written.load(Ordering::Relaxed)
    }

    /// Messages that could not be published: a full queue, or a message whose
    /// blobs overflow the `u16` length field.
    pub fn write_errors(&self) -> u64 {
        self.write_errors.load(Ordering::Relaxed)
    }

    fn record(&self, result: Result<(), EqError>) -> Result<(), EqError> {
        match result {
            Ok(()) => {
                self.messages_written.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                self.write_errors.fetch_add(1, Ordering::Relaxed);
                Err(e)
            }
        }
    }
}

/// The downstream queues of one matching shard: one writer per aggregation
/// shard, and one per logging shard.
pub struct MatchingWriters {
    aggregation: Vec<EqWriter>,
    logging: Vec<EqWriter>,
    stats: std::sync::Arc<WriteStats>,
}

impl MatchingWriters {
    /// Builds the write side over already-constructed writers, in shard order.
    pub fn new(
        aggregation: Vec<EqWriter>,
        logging: Vec<EqWriter>,
        stats: std::sync::Arc<WriteStats>,
    ) -> Self {
        Self {
            aggregation,
            logging,
            stats,
        }
    }

    /// Counters describing what this write side did, shareable with a
    /// supervisor that reports them.
    pub fn stats(&self) -> &std::sync::Arc<WriteStats> {
        &self.stats
    }

    /// Number of aggregation shards, i.e. the modulus for shard selection.
    pub fn aggregation_shards(&self) -> usize {
        self.aggregation.len()
    }

    /// Whether there is anywhere to write. A core built without downstream
    /// queues still matches flows; it just has no output.
    pub fn is_empty(&self) -> bool {
        self.aggregation.is_empty() && self.logging.is_empty()
    }

    fn agg(&mut self, shard: usize) -> Result<&mut EqWriter, EqError> {
        self.aggregation.get_mut(shard).ok_or(EqError::InvalidArg)
    }

    fn log(&mut self, shard: usize) -> Result<&mut EqWriter, EqError> {
        self.logging.get_mut(shard).ok_or(EqError::InvalidArg)
    }

    /// `agg_root_start`: announces a new aggregation root span.
    pub fn agg_root_start(&mut self, shard: usize, ts: u64, r: u64) -> Result<(), EqError> {
        let size = MessageSize::fixed(agg_wire::AGG_ROOT_START_WIRE_SIZE as u32)?;
        let result = self.agg(shard)?.write_message(size, |dest, len| {
            agg_enc::ebpf_net_aggregation_encode_agg_root_start(dest, len, ts, r);
        });
        self.stats.record(result)
    }

    /// `agg_root_end`: releases an aggregation root span.
    pub fn agg_root_end(&mut self, shard: usize, ts: u64, r: u64) -> Result<(), EqError> {
        let size = MessageSize::fixed(agg_wire::AGG_ROOT_END_WIRE_SIZE as u32)?;
        let result = self.agg(shard)?.write_message(size, |dest, len| {
            agg_enc::ebpf_net_aggregation_encode_agg_root_end(dest, len, ts, r);
        });
        self.stats.record(result)
    }

    /// `update_node`: one side's fully resolved node data.
    pub fn update_node(
        &mut self,
        shard: usize,
        ts: u64,
        r: u64,
        side: u8,
        n: &NodeData,
    ) -> Result<(), EqError> {
        let size = MessageSize::dynamic(
            agg_wire::UPDATE_NODE_WIRE_SIZE as u32,
            [
                n.id.len(),
                n.az.len(),
                n.role.len(),
                n.version.len(),
                n.env.len(),
                n.ns.len(),
                n.address.len(),
                n.comm.len(),
                n.container_name.len(),
                n.pod_name.len(),
                n.role_uid.len(),
            ],
        )?;
        let result = self.agg(shard)?.write_message(size, |dest, len| {
            agg_enc::ebpf_net_aggregation_encode_update_node(
                dest,
                len,
                ts,
                r,
                side,
                blob(&n.id),
                blob(&n.az),
                blob(&n.role),
                blob(&n.version),
                blob(&n.env),
                blob(&n.ns),
                n.node_type as u8,
                blob(&n.address),
                blob(&n.comm),
                blob(&n.container_name),
                blob(&n.pod_name),
                blob(&n.role_uid),
            );
        });
        self.stats.record(result)
    }

    /// `update_tcp_metrics` for one direction of one aggregation root.
    pub fn update_tcp_metrics(
        &mut self,
        shard: usize,
        ts: u64,
        r: u64,
        direction: u8,
        m: &TcpMetrics,
    ) -> Result<(), EqError> {
        let size = MessageSize::fixed(agg_wire::UPDATE_TCP_METRICS_WIRE_SIZE as u32)?;
        let result = self.agg(shard)?.write_message(size, |dest, len| {
            agg_enc::ebpf_net_aggregation_encode_update_tcp_metrics(
                dest,
                len,
                ts,
                r,
                direction,
                m.active_sockets,
                m.sum_retrans,
                m.sum_bytes,
                m.sum_srtt,
                m.sum_delivered,
                m.active_rtts,
                m.syn_timeouts,
                m.new_sockets,
                m.tcp_resets,
            );
        });
        self.stats.record(result)
    }

    /// `update_udp_metrics` for one direction of one aggregation root.
    pub fn update_udp_metrics(
        &mut self,
        shard: usize,
        ts: u64,
        r: u64,
        direction: u8,
        m: &UdpMetrics,
    ) -> Result<(), EqError> {
        let size = MessageSize::fixed(agg_wire::UPDATE_UDP_METRICS_WIRE_SIZE as u32)?;
        let result = self.agg(shard)?.write_message(size, |dest, len| {
            agg_enc::ebpf_net_aggregation_encode_update_udp_metrics(
                dest,
                len,
                ts,
                r,
                direction,
                m.active_sockets,
                m.addr_changes,
                m.packets,
                m.bytes,
                m.drops,
            );
        });
        self.stats.record(result)
    }

    /// `update_http_metrics` for one direction of one aggregation root.
    pub fn update_http_metrics(
        &mut self,
        shard: usize,
        ts: u64,
        r: u64,
        direction: u8,
        m: &HttpMetrics,
    ) -> Result<(), EqError> {
        let size = MessageSize::fixed(agg_wire::UPDATE_HTTP_METRICS_WIRE_SIZE as u32)?;
        let result = self.agg(shard)?.write_message(size, |dest, len| {
            agg_enc::ebpf_net_aggregation_encode_update_http_metrics(
                dest,
                len,
                ts,
                r,
                direction,
                m.active_sockets,
                m.sum_code_200,
                m.sum_code_400,
                m.sum_code_500,
                m.sum_code_other,
                m.sum_total_time_ns,
                m.sum_processing_time_ns,
            );
        });
        self.stats.record(result)
    }

    /// `update_dns_metrics` for one direction of one aggregation root.
    pub fn update_dns_metrics(
        &mut self,
        shard: usize,
        ts: u64,
        r: u64,
        direction: u8,
        m: &DnsMetrics,
    ) -> Result<(), EqError> {
        let size = MessageSize::fixed(agg_wire::UPDATE_DNS_METRICS_WIRE_SIZE as u32)?;
        let result = self.agg(shard)?.write_message(size, |dest, len| {
            agg_enc::ebpf_net_aggregation_encode_update_dns_metrics(
                dest,
                len,
                ts,
                r,
                direction,
                m.active_sockets,
                m.requests_a,
                m.requests_aaaa,
                m.responses,
                m.timeouts,
                m.sum_total_time_ns,
                m.sum_processing_time_ns,
            );
        });
        self.stats.record(result)
    }

    /// `logger_start`: opens this core's logger span on the logging core, as
    /// `MatchingCore`'s constructor does with `index_.logger.alloc()`.
    pub fn logger_start(&mut self, shard: usize, ts: u64, r: u64) -> Result<(), EqError> {
        let size = MessageSize::fixed(log_wire::LOGGER_START_WIRE_SIZE as u32)?;
        let result = self.log(shard)?.write_message(size, |dest, len| {
            log_enc::ebpf_net_logging_encode_logger_start(dest, len, ts, r);
        });
        self.stats.record(result)
    }

    /// `k8s_container_pod_not_found`: a container references a pod this core
    /// has never seen, the one log the C++ matching core emits from span
    /// handling (`k8s_container_span.cc`).
    pub fn k8s_container_pod_not_found(
        &mut self,
        shard: usize,
        ts: u64,
        r: u64,
        pod_uid_suffix: &[u8; 64],
        pod_uid_hash: u64,
    ) -> Result<(), EqError> {
        let size = MessageSize::fixed(log_wire::K8S_CONTAINER_POD_NOT_FOUND_WIRE_SIZE as u32)?;
        let suffix = *pod_uid_suffix;
        let result = self.log(shard)?.write_message(size, |dest, len| {
            log_enc::ebpf_net_logging_encode_k8s_container_pod_not_found(
                dest,
                len,
                ts,
                r,
                suffix.as_ptr(),
                pod_uid_hash,
            );
        });
        self.stats.record(result)
    }
}
