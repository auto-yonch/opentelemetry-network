//! The matching core's state machine: ingest messages in, aggregation and
//! logging messages out.
//!
//! This is the port of `reducer/matching/flow_span.cc` plus the span
//! lifecycle the render-generated `Index` used to provide. Message payloads
//! land in [`FlowState`] (which owns per-flow enrichment and metric buffers);
//! this module owns everything that is *between* spans: the bounded tables,
//! aggregation-root allocation and reference counting, shard selection, and
//! the writes.
//!
//! Ordering matches the C++ core: metric messages accumulate into the flow,
//! and the timeslot flush resolves nodes, (re)allocates the aggregation root,
//! and only then writes metrics — so a flow whose nodes never resolve emits
//! nothing, exactly as `send_*_metrics` bails on an invalid `agg_root`.

use std::collections::HashMap;
use std::sync::Arc;

use element_queue::EqError;
use encoder_ebpf_net_matching::parsed_message as msg;

use super::flow::{
    AggRootKey, AggRootRef, EnrichmentConfig, FlowSide, FlowState, ResolvedNodes, UpdateDirection,
};
use super::output::{MatchingWriters, WriteStats};
use super::tables::{
    image_version, AwsInfo, FlowKey, K8sContainerData, K8sPodData, PodKey, Pool, PoolError,
    AGG_ROOT_POOL_SIZE, AWS_ENRICHMENT_POOL_SIZE, FLOW_POOL_SIZE, K8S_CONTAINER_POOL_SIZE,
    K8S_POD_POOL_SIZE,
};

/// Render field widths of the `agg_root` span key, which the shard hash and
/// the aggregation core both depend on.
const ROLE1_WIDTH: usize = 80;
const ROLE2_WIDTH: usize = 256;
const AZ_WIDTH: usize = 32;

/// Something the core could not do, and would otherwise have to swallow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateError {
    /// A message addressed a span this core does not hold. The C++ core logs
    /// and drops; we report so the caller can count it.
    UnknownReference { rpc_id: u16, reference: u64 },
    /// A span pool is at its render-declared `pool_size`.
    PoolExhausted { pool: &'static str },
    /// A downstream write failed (full queue, or an oversized message).
    Write(EqError),
}

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownReference { rpc_id, reference } => write!(
                f,
                "message {rpc_id} addressed unknown span reference {reference}"
            ),
            Self::PoolExhausted { pool } => write!(f, "{pool} pool exhausted"),
            Self::Write(e) => write!(f, "downstream write failed: {e:?}"),
        }
    }
}

impl std::error::Error for StateError {}

impl From<EqError> for StateError {
    fn from(e: EqError) -> Self {
        Self::Write(e)
    }
}

fn pool_error(pool: &'static str) -> impl Fn(PoolError) -> StateError {
    move |PoolError::Exhausted| StateError::PoolExhausted { pool }
}

/// Truncates to at most `width` bytes without splitting a UTF-8 character.
///
/// The render `string<N>` fields truncate by bytes; keeping the result valid
/// UTF-8 costs at most three bytes and keeps the value printable.
fn truncate(value: &str, width: usize) -> String {
    if value.len() <= width {
        return value.to_string();
    }
    let mut end = width;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

/// The aggregation roots this core has allocated, keyed as the C++ index
/// keyed them, and reference counted: many flows share one root.
struct AggRoots {
    entries: HashMap<AggRootKey, AggRootEntry>,
    by_reference: HashMap<u64, AggRootKey>,
    next_reference: u64,
    capacity: usize,
}

struct AggRootEntry {
    shard: usize,
    reference: u64,
    ref_count: u32,
}

impl AggRoots {
    fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            by_reference: HashMap::new(),
            next_reference: 1,
            capacity,
        }
    }

    /// Which aggregation shard a root belongs to.
    ///
    /// The generated C++ proxy derives this from the `shard_by` fields with
    /// its own hash. Any deterministic function of the same fields keeps
    /// every message for one root on one shard, which is what aggregation
    /// correctness needs; only the distribution across shards differs.
    fn shard_of(key: &AggRootKey, shards: usize) -> usize {
        let mut bytes = Vec::with_capacity(
            key.role1.len() + key.az1.len() + key.role2.len() + key.az2.len() + 3,
        );
        for part in [&key.role1, &key.az1, &key.role2, &key.az2] {
            bytes.extend_from_slice(part.as_bytes());
            bytes.push(0);
        }
        (super::lookup3::uid_to_u64(&bytes) % shards as u64) as usize
    }

    /// Takes a reference on the root for `key`, allocating and announcing it
    /// downstream when this core has not seen it before.
    fn acquire(
        &mut self,
        key: &AggRootKey,
        writers: &mut MatchingWriters,
        timestamp: u64,
    ) -> Result<AggRootRef, StateError> {
        if let Some(entry) = self.entries.get_mut(key) {
            entry.ref_count += 1;
            return Ok(AggRootRef {
                shard: entry.shard,
                reference: entry.reference,
            });
        }

        if self.entries.len() >= self.capacity {
            return Err(StateError::PoolExhausted { pool: "agg_root" });
        }

        let shards = writers.aggregation_shards().max(1);
        let shard = Self::shard_of(key, shards);
        let reference = self.next_reference;
        self.next_reference += 1;

        // Announce before anything references it: the aggregation core must
        // know the root before an update names it.
        writers.agg_root_start(shard, timestamp, reference)?;

        self.entries.insert(
            key.clone(),
            AggRootEntry {
                shard,
                reference,
                ref_count: 1,
            },
        );
        self.by_reference.insert(reference, key.clone());
        Ok(AggRootRef { shard, reference })
    }

    /// Drops a flow's reference, releasing the root downstream when it was
    /// the last one.
    fn release(
        &mut self,
        root: AggRootRef,
        writers: &mut MatchingWriters,
        timestamp: u64,
    ) -> Result<(), StateError> {
        let Some(key) = self.by_reference.get(&root.reference).cloned() else {
            return Ok(());
        };
        let Some(entry) = self.entries.get_mut(&key) else {
            return Ok(());
        };

        entry.ref_count = entry.ref_count.saturating_sub(1);
        if entry.ref_count > 0 {
            return Ok(());
        }

        self.entries.remove(&key);
        self.by_reference.remove(&root.reference);
        writers.agg_root_end(root.shard, timestamp, root.reference)?;
        Ok(())
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}

/// The whole matching core state for one shard.
pub struct MatchingState {
    flows: Pool<FlowKey, FlowState>,
    pods: Pool<PodKey, K8sPodData>,
    containers: Pool<PodKey, K8sContainerData>,
    aws: Pool<u128, AwsInfo>,
    agg_roots: AggRoots,
    writers: MatchingWriters,
    config: EnrichmentConfig,
    /// The logger span this core writes its own logs through.
    logger_reference: u64,
    logging_shard: usize,
    timestamp: u64,
}

impl MatchingState {
    /// Builds the state for one matching shard.
    ///
    /// `config` carries the enrichment flags the C++ core takes on its
    /// constructor (`enable_aws_enrichment`, `enable_autonomous_system_ip`,
    /// geoip availability), following the aggregation port's `enable_id_id`
    /// precedent.
    pub fn new(shard: usize, writers: MatchingWriters, config: EnrichmentConfig) -> Self {
        Self {
            flows: Pool::new(FLOW_POOL_SIZE),
            pods: Pool::new(K8S_POD_POOL_SIZE),
            containers: Pool::new(K8S_CONTAINER_POOL_SIZE),
            aws: Pool::new(AWS_ENRICHMENT_POOL_SIZE),
            agg_roots: AggRoots::new(AGG_ROOT_POOL_SIZE),
            writers,
            config,
            // One logger span per matching shard, as `index_.logger.alloc()`
            // gives the C++ core.
            logger_reference: shard as u64 + 1,
            logging_shard: 0,
            timestamp: 0,
        }
    }

    /// Opens this core's logger span downstream. Mirrors the allocation the
    /// C++ `MatchingCore` constructor performs.
    pub fn start_logger(&mut self, timestamp: u64) -> Result<(), StateError> {
        self.timestamp = timestamp;
        let reference = self.logger_reference;
        self.writers
            .logger_start(self.logging_shard, timestamp, reference)?;
        Ok(())
    }

    /// Advances the current timeslot timestamp, which stamps every write.
    pub fn set_timestamp(&mut self, timestamp: u64) {
        self.timestamp = timestamp;
    }

    /// Counters from the write side.
    pub fn write_stats(&self) -> &Arc<WriteStats> {
        self.writers.stats()
    }

    /// Live flows, for tests and for stats reporting.
    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    /// Live aggregation roots.
    pub fn agg_root_count(&self) -> usize {
        self.agg_roots.len()
    }

    pub fn pod_count(&self) -> usize {
        self.pods.len()
    }

    pub fn container_count(&self) -> usize {
        self.containers.len()
    }

    pub fn aws_count(&self) -> usize {
        self.aws.len()
    }

    fn flow_mut(
        &mut self,
        queue: usize,
        reference: u64,
        rpc_id: u16,
    ) -> Result<&mut FlowState, StateError> {
        self.flows
            .by_ref_mut(queue, reference)
            .ok_or(StateError::UnknownReference { rpc_id, reference })
    }

    // ---- flow lifecycle -------------------------------------------------

    /// `flow_start`: the ingest core reports a socket pair to match.
    pub fn flow_start(&mut self, queue: usize, m: &msg::flow_start) -> Result<(), StateError> {
        let key = FlowKey {
            addr1: m.addr1,
            port1: m.port1,
            addr2: m.addr2,
            port2: m.port2,
        };
        self.flows
            .start(queue, m._ref, key, FlowState::new)
            .map_err(pool_error("flow"))?;
        Ok(())
    }

    /// `flow_end`: releases the flow, and with it its aggregation root.
    pub fn flow_end(&mut self, queue: usize, m: &msg::flow_end) -> Result<(), StateError> {
        // Read the root before the flow can be dropped, so the release below
        // matches the acquire that created it.
        let key = self.flows.key_of(queue, m._ref).copied();
        let Some(key) = key else {
            return Err(StateError::UnknownReference {
                rpc_id: msg::flow_end::RPC_ID,
                reference: m._ref,
            });
        };
        let agg_root = self.flows.by_key(&key).and_then(|flow| flow.agg_root);

        let released = self.flows.end(queue, m._ref);
        // The root is only released when this end dropped the last reference
        // to the flow itself.
        if released && self.flows.by_key(&key).is_none() {
            if let Some(root) = agg_root {
                let timestamp = self.timestamp;
                self.agg_roots.release(root, &mut self.writers, timestamp)?;
            }
        }
        Ok(())
    }

    // ---- flow payload ---------------------------------------------------

    pub fn agent_info(&mut self, queue: usize, m: &msg::agent_info) -> Result<(), StateError> {
        self.flow_mut(queue, m._ref, msg::agent_info::RPC_ID)?
            .agent_info(m);
        Ok(())
    }

    pub fn task_info(&mut self, queue: usize, m: &msg::task_info) -> Result<(), StateError> {
        self.flow_mut(queue, m._ref, msg::task_info::RPC_ID)?
            .task_info(m);
        Ok(())
    }

    pub fn socket_info(&mut self, queue: usize, m: &msg::socket_info) -> Result<(), StateError> {
        self.flow_mut(queue, m._ref, msg::socket_info::RPC_ID)?
            .socket_info(m);
        Ok(())
    }

    pub fn k8s_info(&mut self, queue: usize, m: &msg::k8s_info) -> Result<(), StateError> {
        self.flow_mut(queue, m._ref, msg::k8s_info::RPC_ID)?
            .k8s_info(m);
        Ok(())
    }

    pub fn container_info(
        &mut self,
        queue: usize,
        m: &msg::container_info,
    ) -> Result<(), StateError> {
        self.flow_mut(queue, m._ref, msg::container_info::RPC_ID)?
            .container_info(m);
        Ok(())
    }

    pub fn service_info(&mut self, queue: usize, m: &msg::service_info) -> Result<(), StateError> {
        self.flow_mut(queue, m._ref, msg::service_info::RPC_ID)?
            .service_info(m);
        Ok(())
    }

    pub fn tcp_update(&mut self, queue: usize, m: &msg::tcp_update) -> Result<(), StateError> {
        self.flow_mut(queue, m._ref, msg::tcp_update::RPC_ID)?
            .tcp_update(m);
        Ok(())
    }

    pub fn udp_update(&mut self, queue: usize, m: &msg::udp_update) -> Result<(), StateError> {
        self.flow_mut(queue, m._ref, msg::udp_update::RPC_ID)?
            .udp_update(m);
        Ok(())
    }

    pub fn http_update(&mut self, queue: usize, m: &msg::http_update) -> Result<(), StateError> {
        self.flow_mut(queue, m._ref, msg::http_update::RPC_ID)?
            .http_update(m);
        Ok(())
    }

    pub fn dns_update(&mut self, queue: usize, m: &msg::dns_update) -> Result<(), StateError> {
        self.flow_mut(queue, m._ref, msg::dns_update::RPC_ID)?
            .dns_update(m);
        Ok(())
    }

    // ---- enrichment spans ----------------------------------------------

    pub fn k8s_pod_start(
        &mut self,
        queue: usize,
        m: &msg::k8s_pod_start,
    ) -> Result<(), StateError> {
        let key = PodKey::new(m.uid_suffix, m.uid_hash);
        let made = key.clone();
        self.pods
            .start(queue, m._ref, key, move || K8sPodData {
                key: made,
                ..Default::default()
            })
            .map_err(pool_error("k8s_pod"))?;
        Ok(())
    }

    pub fn set_pod_detail(
        &mut self,
        queue: usize,
        m: &msg::set_pod_detail,
    ) -> Result<(), StateError> {
        let pod = self
            .pods
            .by_ref_mut(queue, m._ref)
            .ok_or(StateError::UnknownReference {
                rpc_id: msg::set_pod_detail::RPC_ID,
                reference: m._ref,
            })?;
        pod.owner_name = m.owner_name.clone();
        pod.owner_uid = m.owner_uid.clone();
        pod.pod_name = m.pod_name.clone();
        pod.ns = m.ns.clone();
        pod.version = m.version.clone();
        Ok(())
    }

    pub fn k8s_pod_end(&mut self, queue: usize, m: &msg::k8s_pod_end) -> Result<(), StateError> {
        if !self.pods.end(queue, m._ref) {
            return Err(StateError::UnknownReference {
                rpc_id: msg::k8s_pod_end::RPC_ID,
                reference: m._ref,
            });
        }
        Ok(())
    }

    pub fn k8s_container_start(
        &mut self,
        queue: usize,
        m: &msg::k8s_container_start,
    ) -> Result<(), StateError> {
        let key = PodKey::new(m.uid_suffix, m.uid_hash);
        let made = key.clone();
        self.containers
            .start(queue, m._ref, key, move || K8sContainerData {
                key: made,
                ..Default::default()
            })
            .map_err(pool_error("k8s_container"))?;
        Ok(())
    }

    /// `set_container_pod`: binds a container to its pod, and logs when the
    /// pod is unknown — the one log `k8s_container_span.cc` emits.
    pub fn set_container_pod(
        &mut self,
        queue: usize,
        m: &msg::set_container_pod,
    ) -> Result<(), StateError> {
        let pod_key = PodKey::new(m.pod_uid_suffix, m.pod_uid_hash);
        let pod_known = self.pods.by_key(&pod_key).is_some();

        let container =
            self.containers
                .by_ref_mut(queue, m._ref)
                .ok_or(StateError::UnknownReference {
                    rpc_id: msg::set_container_pod::RPC_ID,
                    reference: m._ref,
                })?;
        container.name = m.name.clone();
        container.version = image_version(&m.image).to_string();
        container.pod = Some(pod_key);

        if !pod_known {
            let (timestamp, reference, shard) =
                (self.timestamp, self.logger_reference, self.logging_shard);
            self.writers.k8s_container_pod_not_found(
                shard,
                timestamp,
                reference,
                &m.pod_uid_suffix,
                m.pod_uid_hash,
            )?;
        }
        Ok(())
    }

    pub fn k8s_container_end(
        &mut self,
        queue: usize,
        m: &msg::k8s_container_end,
    ) -> Result<(), StateError> {
        if !self.containers.end(queue, m._ref) {
            return Err(StateError::UnknownReference {
                rpc_id: msg::k8s_container_end::RPC_ID,
                reference: m._ref,
            });
        }
        Ok(())
    }

    pub fn aws_enrichment_start(
        &mut self,
        queue: usize,
        m: &msg::aws_enrichment_start,
    ) -> Result<(), StateError> {
        self.aws
            .start(queue, m._ref, m.ip, AwsInfo::default)
            .map_err(pool_error("aws_enrichment"))?;
        Ok(())
    }

    pub fn aws_enrichment(
        &mut self,
        queue: usize,
        m: &msg::aws_enrichment,
    ) -> Result<(), StateError> {
        let info = self
            .aws
            .by_ref_mut(queue, m._ref)
            .ok_or(StateError::UnknownReference {
                rpc_id: msg::aws_enrichment::RPC_ID,
                reference: m._ref,
            })?;
        info.role = m.role.clone();
        info.az = m.az.clone();
        info.id = m.id.clone();
        Ok(())
    }

    pub fn aws_enrichment_end(
        &mut self,
        queue: usize,
        m: &msg::aws_enrichment_end,
    ) -> Result<(), StateError> {
        if !self.aws.end(queue, m._ref) {
            return Err(StateError::UnknownReference {
                rpc_id: msg::aws_enrichment_end::RPC_ID,
                reference: m._ref,
            });
        }
        Ok(())
    }

    // ---- timeslot flush -------------------------------------------------

    /// Ends a timeslot: resolves nodes, keeps aggregation roots current, and
    /// writes every buffered metric.
    ///
    /// Errors are collected rather than thrown at the first failure — one
    /// full downstream queue must not silently strand the other flows — and
    /// returned so the caller can log and count them.
    pub fn flush(&mut self, timestamp: u64) -> Vec<StateError> {
        self.timestamp = timestamp;
        let mut errors = Vec::new();

        // Node resolution reads the enrichment tables while the flow table is
        // held mutably, so the keys are collected first.
        let keys: Vec<FlowKey> = self.flows.values_mut().map(|(key, _)| *key).collect();

        for key in keys {
            if let Err(e) = self.flush_flow(&key, timestamp) {
                errors.push(e);
            }
        }
        errors
    }

    fn flush_flow(&mut self, key: &FlowKey, timestamp: u64) -> Result<(), StateError> {
        let tables = super::tables::SpanTables {
            pods: &self.pods,
            containers: &self.containers,
            aws: &self.aws,
        };
        let Some(flow) = self.flows.by_key_mut(key) else {
            return Ok(());
        };

        if !flow.has_pending_metrics() {
            // `send_*_metrics` is what triggers node resolution in the C++
            // core, so a silent flow resolves nothing and writes nothing.
            return Ok(());
        }

        let resolved = flow.update_nodes_if_required(&tables, &self.config);
        let previous_root = flow.agg_root;

        if let Some(nodes) = resolved {
            self.apply_resolved_nodes(*key, nodes, previous_root, timestamp)?;
        }

        self.write_metrics(*key, timestamp)
    }

    /// Points the flow at the aggregation root its resolved nodes name,
    /// releasing the previous one, then sends both node updates.
    fn apply_resolved_nodes(
        &mut self,
        key: FlowKey,
        nodes: ResolvedNodes,
        previous_root: Option<AggRootRef>,
        timestamp: u64,
    ) -> Result<(), StateError> {
        let Some(agg_key) = nodes.agg_root_key() else {
            // Neither side has a role yet: "can't do anything yet".
            return Ok(());
        };
        let agg_key = AggRootKey {
            role1: truncate(&agg_key.role1, ROLE1_WIDTH),
            az1: truncate(&agg_key.az1, AZ_WIDTH),
            role2: truncate(&agg_key.role2, ROLE2_WIDTH),
            az2: truncate(&agg_key.az2, AZ_WIDTH),
        };

        let root = self
            .agg_roots
            .acquire(&agg_key, &mut self.writers, timestamp)?;

        if previous_root != Some(root) {
            if let Some(previous) = previous_root {
                self.agg_roots
                    .release(previous, &mut self.writers, timestamp)?;
            }
            if let Some(flow) = self.flows.by_key_mut(&key) {
                flow.agg_root = Some(root);
            }
        } else {
            // Same root: undo the reference this acquire just took.
            self.agg_roots.release(root, &mut self.writers, timestamp)?;
        }

        self.writers.update_node(
            root.shard,
            timestamp,
            root.reference,
            FlowSide::A.as_u8(),
            &nodes.node_a,
        )?;
        self.writers.update_node(
            root.shard,
            timestamp,
            root.reference,
            FlowSide::B.as_u8(),
            &nodes.node_b,
        )?;
        Ok(())
    }

    /// Drains the flow's metric buffers into the aggregation core.
    fn write_metrics(&mut self, key: FlowKey, timestamp: u64) -> Result<(), StateError> {
        let Some(flow) = self.flows.by_key_mut(&key) else {
            return Ok(());
        };
        let Some(root) = flow.agg_root else {
            // No valid aggregation root: the C++ core drops the metrics here
            // too, and the buffers are cleared so they cannot accumulate
            // across timeslots.
            for direction in 0..2 {
                flow.tcp[direction].take();
                flow.udp[direction].take();
                flow.http[direction].take();
                flow.dns[direction].take();
            }
            return Ok(());
        };

        // Drain every buffer first: the writes below need the whole state
        // mutably, and a half-drained flow would double-report on the next
        // timeslot.
        let directions = [UpdateDirection::AToB, UpdateDirection::BToA];
        let drained: Vec<_> = directions
            .into_iter()
            .enumerate()
            .map(|(index, direction)| {
                (
                    direction,
                    flow.tcp[index].take(),
                    flow.udp[index].take(),
                    flow.http[index].take(),
                    flow.dns[index].take(),
                )
            })
            .collect();

        for (direction, tcp, udp, http, dns) in drained {
            if let Some(m) = tcp {
                self.writers.update_tcp_metrics(
                    root.shard,
                    timestamp,
                    root.reference,
                    direction.as_u8(),
                    &m,
                )?;
            }
            if let Some(m) = udp {
                self.writers.update_udp_metrics(
                    root.shard,
                    timestamp,
                    root.reference,
                    direction.as_u8(),
                    &m,
                )?;
            }
            if let Some(m) = http {
                self.writers.update_http_metrics(
                    root.shard,
                    timestamp,
                    root.reference,
                    direction.as_u8(),
                    &m,
                )?;
            }
            if let Some(m) = dns {
                self.writers.update_dns_metrics(
                    root.shard,
                    timestamp,
                    root.reference,
                    direction.as_u8(),
                    &m,
                )?;
            }
        }
        Ok(())
    }
}
