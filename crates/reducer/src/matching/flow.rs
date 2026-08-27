//! Port of `reducer/matching/flow_span.{h,cc}`: the per-flow state and the
//! node resolution that turns raw agent messages into the two nodes an
//! aggregation root is keyed on.
//!
//! One [`FlowState`] is the Rust stand-in for one C++ `FlowSpan`. The generated
//! span pool, the render metric buffers and the pod/agg-root handles are all
//! hand-rolled here (per the spec's locked decision), but the *behaviour* is a
//! straight port: same enrichment order, same side/direction rules, same
//! caching of node updates.
//!
//! Enrichment order, richest first (`resolve_node`):
//!
//! ```text
//! k8s pod  ->  container info  ->  agent (process)  ->  AWS  ->  DNS  ->  IP
//! ```
//!
//! then a small set of overrides (kubelet, DNS port, instance metadata) that
//! win over whatever the ladder produced.

use encoder_ebpf_net_matching::parsed_message as msg;

use super::cgroup;
use super::ip::{IPv6Address, ADDR_INSTANCE_METADATA};
use super::tables::{K8sPodData, PodKey, SpanTables};

/// `kUnknown`.
pub const UNKNOWN: &str = "(unknown)";
/// Environment reported for a node with no agent behind it.
pub const NO_AGENT_ENVIRONMENT_NAME: &str = "(no agent)";
/// `kCommKubelet`.
pub const COMM_KUBELET: &str = "kubelet";
/// `kPortDNS`.
pub const PORT_DNS: u16 = 53;
/// Role reported for an IP node inside a known autonomous system.
pub const ROLE_INTERNET: &str = "(internet)";
/// Role reported for an IP node with nothing else known about it.
pub const ROLE_UNKNOWN: &str = UNKNOWN;

/// Which end of the flow a message describes (`FlowSide`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowSide {
    A,
    B,
}

impl FlowSide {
    /// `u8_to_side`: anything other than 0 is side B, as the C++ cast does.
    pub fn from_u8(value: u8) -> Self {
        if value == 0 {
            Self::A
        } else {
            Self::B
        }
    }

    /// The other end (`operator~`).
    pub fn flip(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }

    /// Array index (`operator+`).
    pub fn index(self) -> usize {
        match self {
            Self::A => 0,
            Self::B => 1,
        }
    }

    /// Wire value.
    pub fn as_u8(self) -> u8 {
        self.index() as u8
    }
}

/// Direction a metric update applies to (`UpdateDirection`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateDirection {
    None,
    AToB,
    BToA,
}

impl UpdateDirection {
    /// Wire value, matching the C++ enum's underlying integers.
    pub fn as_u8(self) -> u8 {
        match self {
            Self::None => 0,
            Self::AToB => 1,
            Self::BToA => 2,
        }
    }
}

/// How a node was resolved (`NodeResolutionType`). The integer values are on
/// the wire, so they are pinned to the C++ enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum NodeResolutionType {
    #[default]
    None = 0,
    Ip = 1,
    Dns = 2,
    Aws = 3,
    InstanceMetadata = 4,
    Process = 5,
    Localhost = 6,
    K8sContainer = 7,
    Container = 8,
    Nomad = 9,
}

impl NodeResolutionType {
    /// `sanitize_enum`: an out-of-range wire value falls back to `CONTAINER`,
    /// which is what `container_info` does with an unrecognised `node_type`.
    pub fn from_container_wire(value: u8) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Ip,
            2 => Self::Dns,
            3 => Self::Aws,
            4 => Self::InstanceMetadata,
            5 => Self::Process,
            6 => Self::Localhost,
            7 => Self::K8sContainer,
            8 => Self::Container,
            9 => Self::Nomad,
            _ => Self::Container,
        }
    }
}

/// Per-side agent identity (`FlowSpan::AgentInfo`).
#[derive(Debug, Clone, Default)]
pub struct AgentInfo {
    pub id: String,
    pub az: String,
    pub env: String,
    pub role: String,
    pub ns: String,
}

/// Per-side task identity (`FlowSpan::TaskInfo`).
#[derive(Debug, Clone, Default)]
pub struct TaskInfo {
    pub comm: String,
    pub cgroup_name: String,
}

/// Per-side socket endpoints (`FlowSpan::SocketInfo`).
#[derive(Debug, Clone, Default)]
pub struct SocketInfo {
    pub local_addr: IPv6Address,
    pub local_port: u16,
    pub remote_addr: IPv6Address,
    pub remote_port: u16,
    pub is_connector: u8,
    pub remote_dns_name: String,
}

/// Per-side pod identity (`FlowSpan::K8sInfo`).
#[derive(Debug, Clone)]
pub struct K8sInfo {
    pub pod_uid_suffix: [u8; 64],
    pub pod_uid_hash: u64,
}

impl K8sInfo {
    /// The key this info looks a pod up by.
    pub fn key(&self) -> PodKey {
        PodKey::new(self.pod_uid_suffix, self.pod_uid_hash)
    }
}

/// Per-side container identity (`FlowSpan::ContainerInfo`).
#[derive(Debug, Clone)]
pub struct ContainerInfo {
    pub name: String,
    pub pod: String,
    pub role: String,
    pub version: String,
    pub ns: String,
    pub node_type: NodeResolutionType,
}

/// Per-side service identity (`FlowSpan::ServiceInfo`).
#[derive(Debug, Clone, Default)]
pub struct ServiceInfo {
    pub name: String,
}

/// One endpoint of a flow, fully resolved (`FlowSpan::NodeData`). This is
/// exactly the argument list of the `update_node` message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeData {
    pub id: String,
    pub az: String,
    pub role: String,
    pub role_uid: String,
    pub version: String,
    pub env: String,
    pub ns: String,
    pub node_type: NodeResolutionType,
    pub address: String,
    pub comm: String,
    pub container_name: String,
    pub pod_name: String,
}

/// Accumulation of a metric point into a per-timeslot buffer, the operation
/// the render-generated metric buffers perform on every update.
pub trait Accumulate {
    fn accumulate(&mut self, other: &Self);
}

/// TCP metrics for one direction over one timeslot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TcpMetrics {
    pub active_sockets: u32,
    pub sum_retrans: u32,
    pub sum_bytes: u64,
    pub sum_srtt: u64,
    pub sum_delivered: u64,
    pub active_rtts: u32,
    pub syn_timeouts: u32,
    pub new_sockets: u32,
    pub tcp_resets: u32,
}

impl Accumulate for TcpMetrics {
    fn accumulate(&mut self, o: &Self) {
        self.active_sockets = self.active_sockets.wrapping_add(o.active_sockets);
        self.sum_retrans = self.sum_retrans.wrapping_add(o.sum_retrans);
        self.sum_bytes = self.sum_bytes.wrapping_add(o.sum_bytes);
        self.sum_srtt = self.sum_srtt.wrapping_add(o.sum_srtt);
        self.sum_delivered = self.sum_delivered.wrapping_add(o.sum_delivered);
        self.active_rtts = self.active_rtts.wrapping_add(o.active_rtts);
        self.syn_timeouts = self.syn_timeouts.wrapping_add(o.syn_timeouts);
        self.new_sockets = self.new_sockets.wrapping_add(o.new_sockets);
        self.tcp_resets = self.tcp_resets.wrapping_add(o.tcp_resets);
    }
}

/// UDP metrics for one direction over one timeslot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UdpMetrics {
    pub active_sockets: u32,
    pub addr_changes: u32,
    pub packets: u32,
    pub bytes: u64,
    pub drops: u32,
}

impl Accumulate for UdpMetrics {
    fn accumulate(&mut self, o: &Self) {
        self.active_sockets = self.active_sockets.wrapping_add(o.active_sockets);
        self.addr_changes = self.addr_changes.wrapping_add(o.addr_changes);
        self.packets = self.packets.wrapping_add(o.packets);
        self.bytes = self.bytes.wrapping_add(o.bytes);
        self.drops = self.drops.wrapping_add(o.drops);
    }
}

/// HTTP metrics for one direction over one timeslot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HttpMetrics {
    pub active_sockets: u32,
    pub sum_code_200: u32,
    pub sum_code_400: u32,
    pub sum_code_500: u32,
    pub sum_code_other: u32,
    pub sum_total_time_ns: u64,
    pub sum_processing_time_ns: u64,
}

impl Accumulate for HttpMetrics {
    fn accumulate(&mut self, o: &Self) {
        self.active_sockets = self.active_sockets.wrapping_add(o.active_sockets);
        self.sum_code_200 = self.sum_code_200.wrapping_add(o.sum_code_200);
        self.sum_code_400 = self.sum_code_400.wrapping_add(o.sum_code_400);
        self.sum_code_500 = self.sum_code_500.wrapping_add(o.sum_code_500);
        self.sum_code_other = self.sum_code_other.wrapping_add(o.sum_code_other);
        self.sum_total_time_ns = self.sum_total_time_ns.wrapping_add(o.sum_total_time_ns);
        self.sum_processing_time_ns = self
            .sum_processing_time_ns
            .wrapping_add(o.sum_processing_time_ns);
    }
}

/// DNS metrics for one direction over one timeslot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsMetrics {
    pub active_sockets: u32,
    pub requests_a: u32,
    pub requests_aaaa: u32,
    pub responses: u32,
    pub timeouts: u32,
    pub sum_total_time_ns: u64,
    pub sum_processing_time_ns: u64,
}

impl Accumulate for DnsMetrics {
    fn accumulate(&mut self, o: &Self) {
        self.active_sockets = self.active_sockets.wrapping_add(o.active_sockets);
        self.requests_a = self.requests_a.wrapping_add(o.requests_a);
        self.requests_aaaa = self.requests_aaaa.wrapping_add(o.requests_aaaa);
        self.responses = self.responses.wrapping_add(o.responses);
        self.timeouts = self.timeouts.wrapping_add(o.timeouts);
        self.sum_total_time_ns = self.sum_total_time_ns.wrapping_add(o.sum_total_time_ns);
        self.sum_processing_time_ns = self
            .sum_processing_time_ns
            .wrapping_add(o.sum_processing_time_ns);
    }
}

/// One direction's metric buffer for one timeslot.
///
/// `dirty` is what distinguishes "no update arrived" from "an update arrived
/// whose values happen to be zero": the render metric buffers only invoke the
/// timeslot callback for the former, and so does [`MetricBuffer::take`].
#[derive(Debug, Clone, Default)]
pub struct MetricBuffer<T> {
    value: T,
    dirty: bool,
}

impl<T: Accumulate + Default> MetricBuffer<T> {
    /// Accumulates one metric point, marking the buffer for the next flush.
    pub fn add(&mut self, point: &T) {
        self.value.accumulate(point);
        self.dirty = true;
    }

    /// Takes the accumulated value if anything was added since the last take,
    /// resetting the buffer for the new timeslot.
    pub fn take(&mut self) -> Option<T> {
        if !self.dirty {
            return None;
        }
        self.dirty = false;
        Some(std::mem::take(&mut self.value))
    }

    /// Whether an update landed in this buffer since the last take.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }
}

/// Enrichment behaviour, fixed for the life of the core and passed in by the
/// constructor — the `enable_id_id` pattern from the aggregation port.
#[derive(Clone, Default)]
pub struct EnrichmentConfig {
    /// `--enable-aws-enrichment`: consult AWS metadata spans when no agent is
    /// present on a side.
    pub aws_enrichment_enabled: bool,
    /// `--enable-autonomous-system-ip`: keep the real address on IP nodes that
    /// belong to a known autonomous system, instead of collapsing them to
    /// `"AS"`.
    pub autonomous_system_ip_enabled: bool,
    /// GeoIP autonomous-system lookup: address -> AS organization name.
    ///
    /// The C++ core reads this from `MatchingCore::an_db`, a MaxMind database
    /// opened at startup. It is injected here so the port has no I/O of its
    /// own: the shell supplies the real database at switchover, and tests
    /// supply a closure.
    pub autonomous_system_lookup: Option<std::sync::Arc<dyn Fn(&IPv6Address) -> Option<String>>>,
}

impl std::fmt::Debug for EnrichmentConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrichmentConfig")
            .field("aws_enrichment_enabled", &self.aws_enrichment_enabled)
            .field(
                "autonomous_system_ip_enabled",
                &self.autonomous_system_ip_enabled,
            )
            .field(
                "autonomous_system_lookup",
                &self.autonomous_system_lookup.is_some(),
            )
            .finish()
    }
}

/// Address and port of one end of the flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddrPort {
    pub addr: IPv6Address,
    pub port: u16,
}

/// Everything one flow knows about itself: the C++ `FlowSpan` members, plus
/// the handles the generated span carried for it (agg root, enriched pods).
#[derive(Debug, Default)]
pub struct FlowState {
    agent_info: [Option<AgentInfo>; 2],
    task_info: [Option<TaskInfo>; 2],
    socket_info: [Option<SocketInfo>; 2],
    k8s_info: [Option<K8sInfo>; 2],
    container_info: [Option<ContainerInfo>; 2],
    service_info: [Option<ServiceInfo>; 2],

    /// Pods each side has already been enriched with, the hand-rolled
    /// equivalent of the `k8s_pod1`/`k8s_pod2` span references.
    k8s_pod: [Option<PodKey>; 2],

    /// Side that won the right to report metrics, so the two agents on a flow
    /// do not double count.
    metrics_update_side: Option<FlowSide>,

    /// Messages received since creation, and the count at the last node
    /// update: together they suppress redundant `update_node` traffic.
    n_received_info_messages: u32,
    message_count_on_last_update: Option<u32>,

    /// The aggregation root this flow currently reports into, if one has been
    /// allocated. The flow table owns the allocation and reference-counts it.
    pub agg_root: Option<AggRootRef>,

    pub tcp: [MetricBuffer<TcpMetrics>; 2],
    pub udp: [MetricBuffer<UdpMetrics>; 2],
    pub http: [MetricBuffer<HttpMetrics>; 2],
    pub dns: [MetricBuffer<DnsMetrics>; 2],
}

/// A handle on an allocated aggregation root: which shard it lives on and the
/// reference the aggregation core knows it by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AggRootRef {
    pub shard: usize,
    pub reference: u64,
}

/// The key an aggregation root is allocated under: `(role1, az1, role2, az2)`,
/// already ordered.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AggRootKey {
    pub role1: String,
    pub az1: String,
    pub role2: String,
    pub az2: String,
}

/// The two nodes of a flow, as resolved for one node update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedNodes {
    pub node_a: NodeData,
    pub node_b: NodeData,
}

impl ResolvedNodes {
    /// `create_agg_root`'s key derivation.
    ///
    /// Roles alone are not enough to shard on when one side is a bare IP node,
    /// whose role is `(unknown)` or `(internet)`; in that case the AZs join
    /// the key. The pair is then ordered so both agents of a flow compute the
    /// same key. Returns `None` while either role is still unknown — the C++
    /// code allocates nothing until both sides have a role.
    pub fn agg_root_key(&self) -> Option<AggRootKey> {
        if self.node_a.role.is_empty() || self.node_b.role.is_empty() {
            return None;
        }

        let (az_a, az_b) = if self.node_a.node_type == NodeResolutionType::Ip
            || self.node_b.node_type == NodeResolutionType::Ip
        {
            (self.node_a.az.as_str(), self.node_b.az.as_str())
        } else {
            ("", "")
        };

        let a = (self.node_a.role.as_str(), az_a);
        let b = (self.node_b.role.as_str(), az_b);
        let (first, second) = if a <= b { (a, b) } else { (b, a) };

        Some(AggRootKey {
            role1: first.0.to_string(),
            az1: first.1.to_string(),
            role2: second.0.to_string(),
            az2: second.1.to_string(),
        })
    }
}

impl FlowState {
    /// A flow with nothing known about it yet, as `flow_start` creates it.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of info messages this flow has absorbed. Exposed for tests and
    /// for the update-caching check.
    pub fn info_message_count(&self) -> u32 {
        self.n_received_info_messages
    }

    pub fn agent_info(&mut self, m: &msg::agent_info) {
        self.agent_info[FlowSide::from_u8(m.side).index()] = Some(AgentInfo {
            id: m.id.clone(),
            az: m.az.clone(),
            env: m.env.clone(),
            role: m.role.clone(),
            ns: m.ns.clone(),
        });
        self.n_received_info_messages = self.n_received_info_messages.wrapping_add(1);
    }

    pub fn task_info(&mut self, m: &msg::task_info) {
        self.task_info[FlowSide::from_u8(m.side).index()] = Some(TaskInfo {
            comm: m.comm.clone(),
            cgroup_name: m.cgroup_name.clone(),
        });
        self.n_received_info_messages = self.n_received_info_messages.wrapping_add(1);
    }

    pub fn socket_info(&mut self, m: &msg::socket_info) {
        self.socket_info[FlowSide::from_u8(m.side).index()] = Some(SocketInfo {
            local_addr: IPv6Address::from_bytes(m.local_addr),
            local_port: m.local_port,
            remote_addr: IPv6Address::from_bytes(m.remote_addr),
            remote_port: m.remote_port,
            is_connector: m.is_connector,
            remote_dns_name: m.remote_dns_name.clone(),
        });
        self.n_received_info_messages = self.n_received_info_messages.wrapping_add(1);
    }

    pub fn k8s_info(&mut self, m: &msg::k8s_info) {
        self.k8s_info[FlowSide::from_u8(m.side).index()] = Some(K8sInfo {
            pod_uid_suffix: m.pod_uid_suffix,
            pod_uid_hash: m.pod_uid_hash,
        });
        self.n_received_info_messages = self.n_received_info_messages.wrapping_add(1);
    }

    pub fn container_info(&mut self, m: &msg::container_info) {
        self.container_info[FlowSide::from_u8(m.side).index()] = Some(ContainerInfo {
            name: m.name.clone(),
            pod: m.pod.clone(),
            role: m.role.clone(),
            version: m.version.clone(),
            ns: m.ns.clone(),
            node_type: NodeResolutionType::from_container_wire(m.node_type),
        });
        self.n_received_info_messages = self.n_received_info_messages.wrapping_add(1);
    }

    pub fn service_info(&mut self, m: &msg::service_info) {
        self.service_info[FlowSide::from_u8(m.side).index()] = Some(ServiceInfo {
            name: m.name.clone(),
        });
        self.n_received_info_messages = self.n_received_info_messages.wrapping_add(1);
    }

    /// `metrics_update_direction`: the first side to report claims the flow's
    /// metrics; the other side's updates are dropped so a flow observed by two
    /// agents is not counted twice.
    fn metrics_update_direction(
        &mut self,
        side: FlowSide,
        is_rx: bool,
        force_both_sides: bool,
    ) -> UpdateDirection {
        if !force_both_sides {
            match self.metrics_update_side {
                None => self.metrics_update_side = Some(side),
                Some(owner) if owner != side => return UpdateDirection::None,
                Some(_) => {}
            }
        }

        match (side, is_rx) {
            (FlowSide::A, false) => UpdateDirection::AToB,
            (FlowSide::A, true) => UpdateDirection::BToA,
            (FlowSide::B, false) => UpdateDirection::BToA,
            (FlowSide::B, true) => UpdateDirection::AToB,
        }
    }

    /// `tcp_update`. RTT samples are attributed to the side that measured
    /// them, which is the opposite direction from the byte counters, so a
    /// TX-side update carries both a full point and an RTT-only point.
    pub fn tcp_update(&mut self, m: &msg::tcp_update) {
        let side = FlowSide::from_u8(m.side);
        let is_rx = m.is_rx != 0;
        let direction = self.metrics_update_direction(side, is_rx, false);

        let mut point = TcpMetrics {
            active_sockets: m.active_sockets,
            sum_retrans: m.sum_retrans,
            sum_bytes: m.sum_bytes,
            sum_srtt: m.sum_srtt,
            sum_delivered: m.sum_delivered,
            active_rtts: m.active_rtts,
            syn_timeouts: m.syn_timeouts,
            new_sockets: m.new_sockets,
            tcp_resets: m.tcp_resets,
        };

        // RX-side RTT measurements are the peer's, and would double count.
        let skip_rtts = is_rx;
        if skip_rtts {
            point.sum_srtt = 0;
            point.active_rtts = 0;
        }

        match direction {
            UpdateDirection::AToB => self.tcp[0].add(&point),
            UpdateDirection::BToA => self.tcp[1].add(&point),
            UpdateDirection::None => {}
        }

        if !skip_rtts {
            let rtt = TcpMetrics {
                sum_srtt: point.sum_srtt,
                active_rtts: point.active_rtts,
                ..Default::default()
            };
            match direction {
                UpdateDirection::AToB => self.tcp[1].add(&rtt),
                UpdateDirection::BToA => self.tcp[0].add(&rtt),
                UpdateDirection::None => {
                    self.tcp[0].add(&rtt);
                    self.tcp[1].add(&rtt);
                }
            }
        }
    }

    /// `udp_update`.
    pub fn udp_update(&mut self, m: &msg::udp_update) {
        let side = FlowSide::from_u8(m.side);
        let direction = self.metrics_update_direction(side, m.is_rx != 0, false);
        let point = UdpMetrics {
            active_sockets: m.active_sockets,
            addr_changes: m.addr_changes,
            packets: m.packets,
            bytes: m.bytes,
            drops: m.drops,
        };
        match direction {
            UpdateDirection::AToB => self.udp[0].add(&point),
            UpdateDirection::BToA => self.udp[1].add(&point),
            UpdateDirection::None => {}
        }
    }

    /// `http_update`. Timing is split by role — clients report total time,
    /// servers report processing time — and when the other side already owns
    /// the flow's metrics the update still goes out with only the
    /// non-duplicating timing fields.
    pub fn http_update(&mut self, m: &msg::http_update) {
        let side = FlowSide::from_u8(m.side);
        // client(0) is 'tx', server(1) is 'rx'
        let is_rx = m.client_server == SC_SERVER;
        let mut direction = self.metrics_update_direction(side, is_rx, false);

        let mut point = HttpMetrics {
            active_sockets: m.active_sockets,
            sum_code_200: m.sum_code_200,
            sum_code_400: m.sum_code_400,
            sum_code_500: m.sum_code_500,
            sum_code_other: m.sum_code_other,
            sum_total_time_ns: m.sum_total_time_ns,
            sum_processing_time_ns: m.sum_processing_time_ns,
        };

        if !is_rx {
            point.sum_processing_time_ns = 0;
        } else {
            point.sum_total_time_ns = 0;
        }

        if direction == UpdateDirection::None {
            point = HttpMetrics {
                sum_total_time_ns: point.sum_total_time_ns,
                sum_processing_time_ns: point.sum_processing_time_ns,
                ..Default::default()
            };
            direction = self.metrics_update_direction(side, is_rx, true);
        }

        match direction {
            UpdateDirection::AToB => self.http[0].add(&point),
            UpdateDirection::BToA => self.http[1].add(&point),
            UpdateDirection::None => {}
        }
    }

    /// `dns_update`, with the same role-split and single-sided fallback as
    /// [`FlowState::http_update`].
    pub fn dns_update(&mut self, m: &msg::dns_update) {
        let side = FlowSide::from_u8(m.side);
        let is_rx = m.client_server == SC_SERVER;
        let mut direction = self.metrics_update_direction(side, is_rx, false);

        let mut point = DnsMetrics {
            active_sockets: m.active_sockets,
            requests_a: m.requests_a,
            requests_aaaa: m.requests_aaaa,
            responses: m.responses,
            timeouts: m.timeouts,
            sum_total_time_ns: m.sum_total_time_ns,
            sum_processing_time_ns: m.sum_processing_time_ns,
        };

        if !is_rx {
            point.sum_processing_time_ns = 0;
        } else {
            point.sum_total_time_ns = 0;
        }

        if direction == UpdateDirection::None {
            point = DnsMetrics {
                sum_total_time_ns: point.sum_total_time_ns,
                sum_processing_time_ns: point.sum_processing_time_ns,
                ..Default::default()
            };
            direction = self.metrics_update_direction(side, is_rx, true);
        }

        match direction {
            UpdateDirection::AToB => self.dns[0].add(&point),
            UpdateDirection::BToA => self.dns[1].add(&point),
            UpdateDirection::None => {}
        }
    }

    /// Whether any metric buffer has an update waiting for the next flush.
    pub fn has_pending_metrics(&self) -> bool {
        self.tcp.iter().any(MetricBuffer::is_dirty)
            || self.udp.iter().any(MetricBuffer::is_dirty)
            || self.http.iter().any(MetricBuffer::is_dirty)
            || self.dns.iter().any(MetricBuffer::is_dirty)
    }

    /// `update_nodes_if_required`: resolves both nodes when a message has
    /// arrived since the last resolution, or when a side still has k8s info
    /// that has not resolved to a pod yet (the pod may have shown up since).
    ///
    /// Returns `None` when nothing changed, which is the common case and the
    /// reason the C++ code keeps the message counter at all.
    pub fn update_nodes_if_required(
        &mut self,
        tables: &SpanTables<'_>,
        config: &EnrichmentConfig,
    ) -> Option<ResolvedNodes> {
        let got_messages = Some(self.n_received_info_messages) != self.message_count_on_last_update;
        let update_needed = got_messages
            || self.should_attempt_k8s_enrichment(FlowSide::A)
            || self.should_attempt_k8s_enrichment(FlowSide::B);

        if !update_needed {
            return None;
        }

        let node_a = self.resolve_node(FlowSide::A, tables, config);
        let node_b = self.resolve_node(FlowSide::B, tables, config);
        self.message_count_on_last_update = Some(self.n_received_info_messages);

        Some(ResolvedNodes { node_a, node_b })
    }

    /// `should_attempt_k8s_enrichment`: retry while a side has pod info but no
    /// pod resolved for it yet.
    fn should_attempt_k8s_enrichment(&self, side: FlowSide) -> bool {
        if self.k8s_pod[side.index()].is_some() {
            return false;
        }
        self.k8s_info[side.index()].is_some()
    }

    /// `get_comm`.
    fn comm(&self, side: FlowSide) -> String {
        self.task_info[side.index()]
            .as_ref()
            .map(|t| t.comm.clone())
            .unwrap_or_default()
    }

    /// `get_addr_port`: this side's local endpoint, or — when this side has no
    /// agent — the peer's view of it as a remote endpoint.
    fn addr_port(&self, side: FlowSide) -> Option<AddrPort> {
        if let Some(local) = &self.socket_info[side.index()] {
            return Some(AddrPort {
                addr: local.local_addr,
                port: local.local_port,
            });
        }
        let remote = self.socket_info[side.flip().index()].as_ref()?;
        Some(AddrPort {
            addr: remote.remote_addr,
            port: remote.remote_port,
        })
    }

    /// `get_id_az`: identity from this side's agent when there is one,
    /// otherwise the peer's view of the address, with the AZ filled in from
    /// the autonomous-system database when it knows the address.
    ///
    /// The third element says whether the address belongs to a known
    /// autonomous system, which decides `(internet)` vs `(unknown)` later.
    fn id_az(&self, side: FlowSide, config: &EnrichmentConfig) -> (String, String, bool) {
        if let Some(agent) = &self.agent_info[side.index()] {
            return (agent.id.clone(), agent.az.clone(), false);
        }

        let mut id = String::new();
        let mut az = UNKNOWN.to_string();
        let mut is_autonomous_system = false;

        if let Some(socket) = &self.socket_info[side.flip().index()] {
            id = socket.remote_addr.tidy_string();
            if let Some(lookup) = &config.autonomous_system_lookup {
                if let Some(organization) = lookup(&socket.remote_addr) {
                    az = organization;
                    is_autonomous_system = true;
                }
            }
        }

        (id, az, is_autonomous_system)
    }

    /// `get_k8s_pod`: the pod behind a side, found either directly from the
    /// pod uid the agent reported, or indirectly through the container id
    /// parsed out of the task's cgroup.
    fn find_k8s_pod<'a>(
        &self,
        side: FlowSide,
        tables: &'a SpanTables<'a>,
    ) -> Option<&'a K8sPodData> {
        if let Some(info) = &self.k8s_info[side.index()] {
            if let Some(pod) = tables.pod_by_key(&info.key()) {
                if !pod.owner_name.is_empty() {
                    return Some(pod);
                }
            }
        }

        let task = self.task_info[side.index()].as_ref()?;
        let container_id = cgroup::parse(&task.cgroup_name).container_id;
        if container_id.is_empty() {
            return None;
        }
        let container = tables.container_by_id(&container_id)?;
        tables.pod_by_key(container.pod.as_ref()?)
    }

    /// `resolve_node`: everything known about one side, collapsed into the
    /// node the aggregation core is told about.
    pub fn resolve_node(
        &mut self,
        side: FlowSide,
        tables: &SpanTables<'_>,
        config: &EnrichmentConfig,
    ) -> NodeData {
        let Some(addr_port) = self.addr_port(side) else {
            // Neither side reported a socket: nothing identifies this end yet.
            return NodeData::default();
        };

        let mut address = addr_port.addr.tidy_string();
        let (mut id, mut az, is_autonomous_system) = self.id_az(side, config);

        let mut role = String::new();
        let mut role_uid = String::new();
        let mut version = String::new();
        let mut container_name = String::new();
        let mut node_type = NodeResolutionType::None;

        let (env, mut ns) = match &self.agent_info[side.index()] {
            Some(agent) => (agent.env.clone(), agent.ns.clone()),
            None => (NO_AGENT_ENVIRONMENT_NAME.to_string(), String::new()),
        };

        let pod_name = self.container_info[side.index()]
            .as_ref()
            .map(|c| c.pod.clone())
            .unwrap_or_default();

        // Enrich, in order of data richness: k8s, container, agent, then the
        // no-agent ladder (AWS -> DNS -> IP).
        if let Some(pod) = self.find_k8s_pod(side, tables) {
            self.k8s_pod[side.index()] = Some(pod.key.clone());

            node_type = NodeResolutionType::K8sContainer;
            role = pod.owner_name.clone();
            role_uid = pod.owner_uid.clone();
            version = pod.version.clone();
            ns = pod.ns.clone();

            if let Some(task) = &self.task_info[side.index()] {
                let container_id = cgroup::parse(&task.cgroup_name).container_id;
                if !container_id.is_empty() {
                    if let Some(container) = tables.container_by_id(&container_id) {
                        container_name = container.name.clone();
                        if !container.version.is_empty() {
                            version = container.version.clone();
                        }
                    }
                }
            }
        } else if let Some(container) = &self.container_info[side.index()] {
            node_type = container.node_type;
            role = container.role.clone();
            version = container.version.clone();
            ns = container.ns.clone();
        } else if let Some(agent) = &self.agent_info[side.index()] {
            node_type = NodeResolutionType::Process;
            role = if let Some(service) = &self.service_info[side.index()] {
                service.name.clone()
            } else if let Some(task) = &self.task_info[side.index()] {
                task.comm.clone()
            } else {
                // Shouldn't happen: an agent always sends task info too.
                agent.role.clone()
            };
            ns = agent.ns.clone();
        } else if let Some(flipside) = &self.socket_info[side.flip().index()] {
            let peer_addr = flipside.remote_addr;
            let aws_info = if config.aws_enrichment_enabled {
                tables.aws_by_ip(&peer_addr)
            } else {
                None
            };

            match aws_info {
                Some(aws) if !aws.role.is_empty() && !aws.az.is_empty() => {
                    node_type = NodeResolutionType::Aws;
                    role = aws.role.clone();
                    az = aws.az.clone();
                    if !aws.id.is_empty() {
                        id = format!("{}/{}", aws.id, id);
                    }
                }
                _ => {
                    if !flipside.remote_dns_name.is_empty() {
                        node_type = NodeResolutionType::Dns;
                        role = flipside.remote_dns_name.clone();
                    } else {
                        node_type = NodeResolutionType::Ip;
                        role = if is_autonomous_system {
                            ROLE_INTERNET.to_string()
                        } else {
                            ROLE_UNKNOWN.to_string()
                        };
                    }
                }
            }
        }

        // Overrides that win over the ladder above.
        if self.comm(side) == COMM_KUBELET {
            role = "kubelet".to_string();
        } else if addr_port.port == PORT_DNS {
            role = "DNS".to_string();
        } else if addr_port.addr == ADDR_INSTANCE_METADATA {
            role = "instance metadata".to_string();
            node_type = NodeResolutionType::InstanceMetadata;
            // The endpoint is the local instance's own metadata service, so it
            // is identified by the *peer's* agent — the one running there.
            if let Some(agent) = &self.agent_info[side.flip().index()] {
                id = agent.id.clone();
                az = agent.az.clone();
            }
        }

        if is_autonomous_system
            && node_type == NodeResolutionType::Ip
            && !config.autonomous_system_ip_enabled
        {
            // Collapse every address in the autonomous system into a single
            // node, instead of one node per remote IP.
            id = "AS".to_string();
            address = "AS".to_string();
        }

        if container_name.is_empty() {
            container_name = self.container_info[side.index()]
                .as_ref()
                .map(|c| c.name.clone())
                .unwrap_or_default();
        }

        NodeData {
            id,
            az,
            role,
            role_uid,
            version,
            env,
            ns,
            node_type,
            address,
            comm: self.comm(side),
            container_name,
            pod_name,
        }
    }
}

/// `SC_SERVER` from `common/client_server_type.h`: the server end of a
/// client/server protocol exchange.
const SC_SERVER: u8 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp_msg(side: u8, is_rx: u8, bytes: u64, srtt: u64, rtts: u32) -> msg::tcp_update {
        msg::tcp_update {
            _rpc_id: msg::tcp_update::RPC_ID,
            _ref: 1,
            side,
            is_rx,
            active_sockets: 1,
            sum_retrans: 0,
            sum_bytes: bytes,
            sum_srtt: srtt,
            sum_delivered: 0,
            active_rtts: rtts,
            syn_timeouts: 0,
            new_sockets: 0,
            tcp_resets: 0,
        }
    }

    /// A TX update from side A counts bytes A->B, and its RTT sample lands on
    /// the reverse direction where the peer's metrics live.
    #[test]
    fn tcp_tx_update_splits_bytes_and_rtt_across_directions() {
        let mut flow = FlowState::new();
        flow.tcp_update(&tcp_msg(0, 0, 4096, 900, 3));

        let a_to_b = flow.tcp[0].take().expect("a->b update");
        let b_to_a = flow.tcp[1].take().expect("b->a rtt update");

        assert_eq!(a_to_b.sum_bytes, 4096);
        assert_eq!(a_to_b.sum_srtt, 900);
        assert_eq!(b_to_a.sum_bytes, 0);
        assert_eq!(b_to_a.sum_srtt, 900);
        assert_eq!(b_to_a.active_rtts, 3);
    }

    /// Byte counters from the second agent to report on a flow are dropped,
    /// so a flow both ends observe is not counted twice.
    #[test]
    fn only_the_first_side_to_report_owns_the_byte_counters() {
        let mut flow = FlowState::new();
        flow.tcp_update(&tcp_msg(0, 0, 1000, 0, 0));
        flow.tcp[0].take();
        flow.tcp[1].take();

        // An RX update from the non-owning side carries no RTT sample of its
        // own, so nothing at all survives.
        flow.tcp_update(&tcp_msg(1, 1, 5000, 700, 4));

        assert!(flow.tcp[0].take().is_none(), "side B must not contribute");
        assert!(flow.tcp[1].take().is_none(), "side B must not contribute");
    }

    /// RTT samples are the exception to metric ownership: the non-owning
    /// side's TX update still contributes its RTT to both directions, because
    /// an RTT the owner never measured is not a duplicate.
    #[test]
    fn the_non_owning_side_still_contributes_rtt_samples() {
        let mut flow = FlowState::new();
        flow.tcp_update(&tcp_msg(0, 0, 1000, 0, 0));
        flow.tcp[0].take();
        flow.tcp[1].take();

        flow.tcp_update(&tcp_msg(1, 0, 5000, 700, 4));

        let a_to_b = flow.tcp[0].take().expect("rtt-only a->b");
        let b_to_a = flow.tcp[1].take().expect("rtt-only b->a");
        for point in [&a_to_b, &b_to_a] {
            assert_eq!(point.sum_srtt, 700);
            assert_eq!(point.active_rtts, 4);
            assert_eq!(point.sum_bytes, 0, "bytes would double count");
            assert_eq!(point.active_sockets, 0, "sockets would double count");
        }
    }

    /// An RX update carries no RTT sample: those belong to the sender.
    #[test]
    fn rx_updates_drop_rtt_samples() {
        let mut flow = FlowState::new();
        flow.tcp_update(&tcp_msg(0, 1, 2048, 700, 5));

        let b_to_a = flow.tcp[1].take().expect("b->a update");
        assert_eq!(b_to_a.sum_bytes, 2048);
        assert_eq!(b_to_a.sum_srtt, 0);
        assert_eq!(b_to_a.active_rtts, 0);
        assert!(flow.tcp[0].take().is_none());
    }

    /// A buffer with no update is skipped entirely; a buffer whose update
    /// happened to be all zeroes is still reported.
    #[test]
    fn metric_buffers_distinguish_no_update_from_zero_update() {
        let mut buffer = MetricBuffer::<UdpMetrics>::default();
        assert!(buffer.take().is_none());

        buffer.add(&UdpMetrics::default());
        assert_eq!(buffer.take(), Some(UdpMetrics::default()));
        assert!(buffer.take().is_none(), "take must reset the buffer");
    }

    /// When both sides are known workloads the key is roles only; ordering
    /// makes it independent of which agent reported first.
    #[test]
    fn agg_root_key_orders_roles_and_omits_az_for_workloads() {
        let nodes = ResolvedNodes {
            node_a: NodeData {
                role: "web".into(),
                az: "us-east-1a".into(),
                node_type: NodeResolutionType::K8sContainer,
                ..Default::default()
            },
            node_b: NodeData {
                role: "api".into(),
                az: "us-east-1b".into(),
                node_type: NodeResolutionType::K8sContainer,
                ..Default::default()
            },
        };

        let key = nodes.agg_root_key().expect("both roles known");
        assert_eq!(key.role1, "api");
        assert_eq!(key.role2, "web");
        assert_eq!(key.az1, "");
        assert_eq!(key.az2, "");
    }

    /// With an IP node on one side the roles are uninformative, so the AZs
    /// join the key.
    #[test]
    fn agg_root_key_includes_az_when_a_side_is_an_ip_node() {
        let nodes = ResolvedNodes {
            node_a: NodeData {
                role: "web".into(),
                az: "us-east-1a".into(),
                node_type: NodeResolutionType::K8sContainer,
                ..Default::default()
            },
            node_b: NodeData {
                role: ROLE_INTERNET.into(),
                az: "AS15169".into(),
                node_type: NodeResolutionType::Ip,
                ..Default::default()
            },
        };

        let key = nodes.agg_root_key().expect("both roles known");
        assert_eq!(
            (key.role1.as_str(), key.az1.as_str()),
            ("(internet)", "AS15169")
        );
        assert_eq!(
            (key.role2.as_str(), key.az2.as_str()),
            ("web", "us-east-1a")
        );
    }

    /// Until both sides have a role there is nothing to aggregate under.
    #[test]
    fn agg_root_key_waits_for_both_roles() {
        let nodes = ResolvedNodes {
            node_a: NodeData {
                role: "web".into(),
                ..Default::default()
            },
            node_b: NodeData::default(),
        };
        assert!(nodes.agg_root_key().is_none());
    }
}
