//! Aggregator: core domain state and API (skeleton).

use std::collections::HashMap;

use crate::aggregation_framework::aggregate;
use crate::internal_events::Counters;
use crate::metrics::{DnsMetrics, HttpMetrics, TcpMetrics, UdpMetrics};
use crate::otlp_encoding::{
    add_node_labels, Labels, OtlpExporter, LABEL_AGGREGATION, LABEL_SF_PRODUCT,
    LABEL_SF_PRODUCT_VALUE,
};
use otlp_export::ffi::Label as OLabel;
use rc_hashmap::{RcHashMap, Ref};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Side {
    A,
    B,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Direction {
    AtoB,
    BtoA,
}

pub type AggRootKey = (usize, u64); // (queue_index, _ref)

#[derive(Default, Debug, Clone, PartialEq, Eq, Hash)]
pub struct Az {
    pub az: String,
    pub role: String,
    pub version: String,
    pub env: String,
    pub ns: String,
    pub node_type: u8,
    pub process: String,
    pub container: String,
    pub role_uid: String,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Hash)]
pub struct Node {
    pub id: String,
    pub address: String,
    pub pod_name: String,
}

type AzRef = Ref<Az, ()>;
type NodeRef = Ref<Node, ()>;

#[derive(Default)]
struct AggRoot {
    a_node: Option<NodeRef>,
    a_az: Option<AzRef>,
    b_node: Option<NodeRef>,
    b_az: Option<AzRef>,
    a_to_b: Option<NodeNodeRef>,
    b_to_a: Option<NodeNodeRef>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct NodeNodeKey {
    src_az: AzRef,
    src_node: NodeRef,
    dst_az: AzRef,
    dst_node: NodeRef,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct NodeAzKey {
    src_az: AzRef,
    src_node: NodeRef,
    dst_az: AzRef,
}
#[derive(Clone, PartialEq, Eq, Hash)]
struct AzNodeKey {
    src_az: AzRef,
    dst_node: NodeRef,
    dst_az: AzRef,
}
#[derive(Clone, PartialEq, Eq, Hash)]
struct AzAzKey {
    src_az: AzRef,
    dst_az: AzRef,
}
#[derive(Default)]
struct NodeNodeEntry {
    metrics: AllMetrics,
    keepalive: Option<NodeNodeRef>,
}

type NodeNodeRef = Ref<NodeNodeKey, NodeNodeEntry>;

// Common labels computation across all keys.
fn compute_labels(
    az_store: &RcHashMap<Az, ()>,
    node_store: &RcHashMap<Node, ()>,
    src_az: &AzRef,
    dst_az: &AzRef,
    src_node: Option<&NodeRef>,
    dst_node: Option<&NodeRef>,
) -> Labels {
    let mut labels: Labels = Vec::new();
    labels.push(OLabel {
        key: LABEL_SF_PRODUCT.to_string(),
        value: LABEL_SF_PRODUCT_VALUE.to_string(),
    });

    let src_az_v = src_az.key(az_store).ok();
    let dst_az_v = dst_az.key(az_store).ok();
    let src_node_v = src_node.and_then(|n| n.key(node_store).ok());
    let dst_node_v = dst_node.and_then(|n| n.key(node_store).ok());

    add_node_labels("source.", src_node_v, src_az_v, &mut labels);
    add_node_labels("dest.", dst_node_v, dst_az_v, &mut labels);

    if let (Some(sa), Some(da)) = (src_az_v, dst_az_v) {
        if !sa.az.is_empty() && !da.az.is_empty() {
            labels.push(OLabel {
                key: "az_equal".to_string(),
                value: (sa.az == da.az).to_string(),
            });
        }
    }
    labels
}

impl NodeNodeKey {
    fn to_otlp_labels(
        &self,
        az_store: &RcHashMap<Az, ()>,
        node_store: &RcHashMap<Node, ()>,
    ) -> Labels {
        let mut labels = compute_labels(
            az_store,
            node_store,
            &self.src_az,
            &self.dst_az,
            Some(&self.src_node),
            Some(&self.dst_node),
        );
        labels.push(OLabel {
            key: LABEL_AGGREGATION.to_string(),
            value: "id_id".to_string(),
        });
        labels
    }
}
impl NodeAzKey {
    fn to_otlp_labels(
        &self,
        az_store: &RcHashMap<Az, ()>,
        node_store: &RcHashMap<Node, ()>,
    ) -> Labels {
        let mut labels = compute_labels(
            az_store,
            node_store,
            &self.src_az,
            &self.dst_az,
            Some(&self.src_node),
            None,
        );
        labels.push(OLabel {
            key: LABEL_AGGREGATION.to_string(),
            value: "id_az".to_string(),
        });
        labels
    }
}
impl AzNodeKey {
    fn to_otlp_labels(
        &self,
        az_store: &RcHashMap<Az, ()>,
        node_store: &RcHashMap<Node, ()>,
    ) -> Labels {
        let mut labels = compute_labels(
            az_store,
            node_store,
            &self.src_az,
            &self.dst_az,
            None,
            Some(&self.dst_node),
        );
        labels.push(OLabel {
            key: LABEL_AGGREGATION.to_string(),
            value: "az_id".to_string(),
        });
        labels
    }
}
impl AzAzKey {
    fn to_otlp_labels(
        &self,
        az_store: &RcHashMap<Az, ()>,
        _node_store: &RcHashMap<Node, ()>,
    ) -> Labels {
        let mut labels = compute_labels(
            az_store,
            _node_store,
            &self.src_az,
            &self.dst_az,
            None,
            None,
        );
        labels.push(OLabel {
            key: LABEL_AGGREGATION.to_string(),
            value: "az_az".to_string(),
        });
        labels
    }
}

#[derive(Default)]
pub struct Aggregator {
    pub events: Counters,

    // Identity stores
    az_store: RcHashMap<Az, ()>,
    node_store: RcHashMap<Node, ()>,

    // Roots and node-node aggregation
    agg_roots: HashMap<AggRootKey, AggRoot>,
    node_node_store: RcHashMap<NodeNodeKey, NodeNodeEntry>,

    // Feature flags (subset for now)
    pub enable_id_id: bool,
    pub enable_az_id: bool,
    pub disable_node_ip_field: bool,
}

impl Aggregator {
    pub fn new() -> Self {
        Self {
            events: Counters::default(),
            az_store: RcHashMap::new(),
            node_store: RcHashMap::new(),
            agg_roots: HashMap::new(),
            node_node_store: RcHashMap::new(),
            enable_id_id: true,
            enable_az_id: true,
            disable_node_ip_field: false,
        }
    }

    pub fn agg_root_start(&mut self, key: AggRootKey) {
        // Insert or reset the root entry
        self.agg_roots.insert(key, AggRoot::default());
    }
    pub fn agg_root_end(&mut self, key: AggRootKey) {
        // Remove only the root; node-node entries persist via keepalive
        let _ = self.agg_roots.remove(&key);
    }

    pub fn update_node(&mut self, key: AggRootKey, side: Side, az: Az, mut node: Node) {
        // Optionally blank IP address for uniqueness if disabled
        if self.disable_node_ip_field {
            node.address.clear();
        }

        // Upsert AZ (intern full Az)
        let az_ref = match self.az_store.find(&az) {
            Some(r) => r,
            None => self.az_store.insert(az, ()).expect("az insert failed"),
        };

        // Upsert Node (intern full Node)
        let node_ref = match self.node_store.find(&node) {
            Some(r) => r,
            None => self
                .node_store
                .insert(node, ())
                .expect("node insert failed"),
        };

        // Upsert root and attach side
        let root = self.agg_roots.entry(key).or_insert_with(AggRoot::default);
        match side {
            Side::A => {
                root.a_az = Some(az_ref.clone());
                root.a_node = Some(node_ref.clone());
            }
            Side::B => {
                root.b_az = Some(az_ref.clone());
                root.b_node = Some(node_ref.clone());
            }
        }

        // If both sides known and node-node refs not set, wire them
        if root.a_to_b.is_none() && root.b_to_a.is_none() {
            if let (Some(a_node), Some(a_az), Some(b_node), Some(b_az)) =
                (&root.a_node, &root.a_az, &root.b_node, &root.b_az)
            {
                let a2b_key = NodeNodeKey {
                    src_az: a_az.clone(),
                    src_node: a_node.clone(),
                    dst_az: b_az.clone(),
                    dst_node: b_node.clone(),
                };
                let b2a_key = NodeNodeKey {
                    src_az: b_az.clone(),
                    src_node: b_node.clone(),
                    dst_az: a_az.clone(),
                    dst_node: a_node.clone(),
                };
                let a2b_ref = match self.node_node_store.find(&a2b_key) {
                    Some(r) => r,
                    None => self
                        .node_node_store
                        .insert(a2b_key, NodeNodeEntry::default())
                        .expect("a2b insert"),
                };
                let b2a_ref = match self.node_node_store.find(&b2a_key) {
                    Some(r) => r,
                    None => self
                        .node_node_store
                        .insert(b2a_key, NodeNodeEntry::default())
                        .expect("b2a insert"),
                };
                root.a_to_b = Some(a2b_ref);
                root.b_to_a = Some(b2a_ref);
            }
        }
    }

    pub fn add_tcp(&mut self, key: AggRootKey, dir: Direction, m: TcpMetrics) {
        if let Some(entry_ref) = self.find_node_node_ref(key, dir) {
            if let Ok(entry) = entry_ref.value_mut(&mut self.node_node_store) {
                if entry.keepalive.is_none() {
                    entry.keepalive = Some(entry_ref.clone());
                }
                entry.metrics.tcp.add_from(&m);
            }
        } else {
            self.events.inc_metric_before_sides_resolved();
        }
    }
    pub fn add_udp(&mut self, key: AggRootKey, dir: Direction, m: UdpMetrics) {
        if let Some(entry_ref) = self.find_node_node_ref(key, dir) {
            if let Ok(entry) = entry_ref.value_mut(&mut self.node_node_store) {
                if entry.keepalive.is_none() {
                    entry.keepalive = Some(entry_ref.clone());
                }
                entry.metrics.udp.add_from(&m);
            }
        } else {
            self.events.inc_metric_before_sides_resolved();
        }
    }
    pub fn add_http(&mut self, key: AggRootKey, dir: Direction, m: HttpMetrics) {
        if let Some(entry_ref) = self.find_node_node_ref(key, dir) {
            if let Ok(entry) = entry_ref.value_mut(&mut self.node_node_store) {
                if entry.keepalive.is_none() {
                    entry.keepalive = Some(entry_ref.clone());
                }
                entry.metrics.http.add_from(&m);
            }
        } else {
            self.events.inc_metric_before_sides_resolved();
        }
    }
    pub fn add_dns(&mut self, key: AggRootKey, dir: Direction, m: DnsMetrics) {
        if let Some(entry_ref) = self.find_node_node_ref(key, dir) {
            if let Ok(entry) = entry_ref.value_mut(&mut self.node_node_store) {
                if entry.keepalive.is_none() {
                    entry.keepalive = Some(entry_ref.clone());
                }
                entry.metrics.dns.add_from(&m);
            }
        } else {
            self.events.inc_metric_before_sides_resolved();
        }
    }

    fn find_node_node_ref(&mut self, key: AggRootKey, dir: Direction) -> Option<NodeNodeRef> {
        let root = match self.agg_roots.get(&key) {
            Some(r) => r,
            None => {
                self.events.inc_missing_root_for_metric();
                return None;
            }
        };
        match dir {
            Direction::AtoB => root.a_to_b.clone(),
            Direction::BtoA => root.b_to_a.clone(),
        }
    }

    /// Compute the node-az, az-node, and az-az rollup projections from the
    /// current node-node store. Pure (no mutation, no exporter dependency) -
    /// this is also the seam characterization tests use to pin rollup
    /// behavior without needing a live `OtlpExporter`.
    fn compute_projections(
        &self,
    ) -> (
        Option<HashMap<NodeAzKey, AllMetrics>>,
        Option<HashMap<AzNodeKey, AllMetrics>>,
        Option<HashMap<AzAzKey, AllMetrics>>,
    ) {
        if !self.enable_az_id {
            return (None, None, None);
        }
        let node_az_map: HashMap<NodeAzKey, AllMetrics> = aggregate(
            self.node_node_store.iter(),
            |it| {
                let k = it.key(&self.node_node_store).unwrap();
                NodeAzKey {
                    src_az: k.src_az.clone(),
                    src_node: k.src_node.clone(),
                    dst_az: k.dst_az.clone(),
                }
            },
            |t: &mut AllMetrics, it| {
                let m = &it.value(&self.node_node_store).unwrap().metrics;
                t.add(m)
            },
        );
        let az_node_map: HashMap<AzNodeKey, AllMetrics> = aggregate(
            self.node_node_store.iter(),
            |it| {
                let k = it.key(&self.node_node_store).unwrap();
                AzNodeKey {
                    src_az: k.src_az.clone(),
                    dst_node: k.dst_node.clone(),
                    dst_az: k.dst_az.clone(),
                }
            },
            |t: &mut AllMetrics, it| {
                let m = &it.value(&self.node_node_store).unwrap().metrics;
                t.add(m)
            },
        );
        // Derive AzAz from NodeAz (avoid recomputing from NodeNode)
        let az_az_map: HashMap<AzAzKey, AllMetrics> = aggregate(
            node_az_map.iter(),
            |&(k, _m)| AzAzKey {
                src_az: k.src_az.clone(),
                dst_az: k.dst_az.clone(),
            },
            |t: &mut AllMetrics, &(_k, m)| t.add(m),
        );
        (Some(node_az_map), Some(az_node_map), Some(az_az_map))
    }

    /// Reset each node-node entry's metrics after a window has been emitted,
    /// carrying forward the "had samples" flags that drive one extra
    /// zero-valued emission (zero-injection) and dropping the keepalive once
    /// every protocol has gone quiet.
    fn reset_after_emit(&mut self) {
        for mut it in self.node_node_store.iter_mut() {
            let e = it.value_mut();
            let had_tcp = !e.metrics.tcp.is_zero();
            let had_udp = !e.metrics.udp.is_zero();
            let had_http = !e.metrics.http.is_zero();
            let had_dns = !e.metrics.dns.is_zero();

            let mut next = AllMetrics::default();
            next.tcp_prev_window_had_samples = had_tcp;
            next.udp_prev_window_had_samples = had_udp;
            next.http_prev_window_had_samples = had_http;
            next.dns_prev_window_had_samples = had_dns;
            e.metrics = next;

            if !(had_tcp || had_udp || had_http || had_dns) {
                e.keepalive = None;
            }
        }
    }

    pub fn output_metrics(&mut self, window_end_ns: u64, exporter: &mut OtlpExporter) {
        // Aggregate projections first (without mutating node-node entries)
        let (node_az_map, az_node_map, az_az_map) = self.compute_projections();

        // Emit node-node (id_id)
        if self.enable_id_id {
            for it in self.node_node_store.iter() {
                let k = it.key(&self.node_node_store).unwrap();
                let m = &it.value(&self.node_node_store).unwrap().metrics;
                if !m.should_emit_any() {
                    continue;
                }
                let labels = k.to_otlp_labels(&self.az_store, &self.node_store);
                exporter.emit_all_metrics(window_end_ns as i64, &labels, m);
            }
        }

        // Emit node-az, az-node, az-az
        if let (Some(node_az_map), Some(az_node_map), Some(az_az_map)) = (
            node_az_map.as_ref(),
            az_node_map.as_ref(),
            az_az_map.as_ref(),
        ) {
            for (k, m) in node_az_map.iter() {
                if !m.should_emit_any() {
                    continue;
                }
                let labels = k.to_otlp_labels(&self.az_store, &self.node_store);
                exporter.emit_all_metrics(window_end_ns as i64, &labels, m);
            }
            for (k, m) in az_node_map.iter() {
                if !m.should_emit_any() {
                    continue;
                }
                let labels = k.to_otlp_labels(&self.az_store, &self.node_store);
                exporter.emit_all_metrics(window_end_ns as i64, &labels, m);
            }
            for (k, m) in az_az_map.iter() {
                if !m.should_emit_any() {
                    continue;
                }
                let labels = k.to_otlp_labels(&self.az_store, &self.node_store);
                exporter.emit_all_metrics(window_end_ns as i64, &labels, m);
            }
        }

        exporter.flush();

        // Cleanup node-node entries after aggregations and emissions
        self.reset_after_emit();
    }
}

#[derive(Default, Clone)]
pub struct AllMetrics {
    pub tcp: TcpMetrics,
    pub udp: UdpMetrics,
    pub http: HttpMetrics,
    pub dns: DnsMetrics,
    pub tcp_prev_window_had_samples: bool,
    pub udp_prev_window_had_samples: bool,
    pub http_prev_window_had_samples: bool,
    pub dns_prev_window_had_samples: bool,
}

impl AllMetrics {
    fn add(&mut self, other: &Self) {
        self.tcp.add_from(&other.tcp);
        self.udp.add_from(&other.udp);
        self.http.add_from(&other.http);
        self.dns.add_from(&other.dns);
        self.tcp_prev_window_had_samples |= other.tcp_prev_window_had_samples;
        self.udp_prev_window_had_samples |= other.udp_prev_window_had_samples;
        self.http_prev_window_had_samples |= other.http_prev_window_had_samples;
        self.dns_prev_window_had_samples |= other.dns_prev_window_had_samples;
    }
    fn should_emit_any(&self) -> bool {
        let tcp_emit = !self.tcp.is_zero() || self.tcp_prev_window_had_samples;
        let udp_emit = !self.udp.is_zero() || self.udp_prev_window_had_samples;
        let http_emit = !self.http.is_zero() || self.http_prev_window_had_samples;
        let dns_emit = !self.dns.is_zero() || self.dns_prev_window_had_samples;
        tcp_emit || udp_emit || http_emit || dns_emit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn az(label: &str) -> Az {
        Az {
            az: label.to_string(),
            ..Default::default()
        }
    }

    fn node(label: &str) -> Node {
        Node {
            id: label.to_string(),
            ..Default::default()
        }
    }

    fn tcp(sum_bytes: u64) -> TcpMetrics {
        TcpMetrics {
            active_sockets: 1,
            sum_bytes,
            ..Default::default()
        }
    }

    #[test]
    fn interning_dedupes_equal_az_and_node_values_and_keeps_distinct_ones() {
        let mut agg = Aggregator::new();
        let az_a = az("az-a");
        let n1 = node("n1");

        agg.agg_root_start((0, 1));
        agg.update_node((0, 1), Side::A, az_a.clone(), n1.clone());
        agg.agg_root_start((0, 2));
        agg.update_node((0, 2), Side::A, az_a.clone(), n1.clone());

        // Same Az/Node values reused across roots intern to a single entry each.
        assert_eq!(agg.az_store.len(), 1);
        assert_eq!(agg.node_store.len(), 1);

        agg.agg_root_start((0, 3));
        agg.update_node((0, 3), Side::A, az("az-b"), node("n2"));

        // A genuinely distinct value grows both stores.
        assert_eq!(agg.az_store.len(), 2);
        assert_eq!(agg.node_store.len(), 2);
    }

    #[test]
    fn all_four_rollup_directions_aggregate_node_node_entries_correctly() {
        let mut agg = Aggregator::new();
        let az_a = az("az-a");
        let az_b = az("az-b");
        let n1 = node("n1");
        let n2 = node("n2");
        let n3 = node("n3");
        let n4 = node("n4");

        // R1: (az_a, n1) -> (az_b, n2), tcp sum_bytes=10
        agg.agg_root_start((0, 1));
        agg.update_node((0, 1), Side::A, az_a.clone(), n1.clone());
        agg.update_node((0, 1), Side::B, az_b.clone(), n2.clone());
        agg.add_tcp((0, 1), Direction::AtoB, tcp(10));

        // R2: same src (az_a, n1) as R1, different dst node -> sum_bytes=20
        agg.agg_root_start((0, 2));
        agg.update_node((0, 2), Side::A, az_a.clone(), n1.clone());
        agg.update_node((0, 2), Side::B, az_b.clone(), n3.clone());
        agg.add_tcp((0, 2), Direction::AtoB, tcp(20));

        // R3: different src node, same dst (az_b, n2) as R1 -> sum_bytes=30
        agg.agg_root_start((0, 3));
        agg.update_node((0, 3), Side::A, az_a.clone(), n4.clone());
        agg.update_node((0, 3), Side::B, az_b.clone(), n2.clone());
        agg.add_tcp((0, 3), Direction::AtoB, tcp(30));

        let src_a_ref = agg.az_store.find(&az_a).unwrap();
        let dst_b_ref = agg.az_store.find(&az_b).unwrap();
        let n1_ref = agg.node_store.find(&n1).unwrap();
        let n2_ref = agg.node_store.find(&n2).unwrap();
        let n3_ref = agg.node_store.find(&n3).unwrap();
        let n4_ref = agg.node_store.find(&n4).unwrap();

        // node-node (id_id): three distinct entries, none collapsed.
        let node_node_bytes = |k: &NodeNodeKey| -> u64 {
            agg.node_node_store
                .find(k)
                .unwrap()
                .value(&agg.node_node_store)
                .unwrap()
                .metrics
                .tcp
                .sum_bytes
        };
        assert_eq!(
            node_node_bytes(&NodeNodeKey {
                src_az: src_a_ref.clone(),
                src_node: n1_ref.clone(),
                dst_az: dst_b_ref.clone(),
                dst_node: n2_ref.clone(),
            }),
            10
        );
        assert_eq!(
            node_node_bytes(&NodeNodeKey {
                src_az: src_a_ref.clone(),
                src_node: n1_ref.clone(),
                dst_az: dst_b_ref.clone(),
                dst_node: n3_ref.clone(),
            }),
            20
        );
        assert_eq!(
            node_node_bytes(&NodeNodeKey {
                src_az: src_a_ref.clone(),
                src_node: n4_ref.clone(),
                dst_az: dst_b_ref.clone(),
                dst_node: n2_ref.clone(),
            }),
            30
        );

        let (node_az_map, az_node_map, az_az_map) = agg.compute_projections();
        let node_az_map = node_az_map.expect("enable_az_id defaults to true");
        let az_node_map = az_node_map.expect("enable_az_id defaults to true");
        let az_az_map = az_az_map.expect("enable_az_id defaults to true");

        // node-az (id_az): (az_a, n1, az_b) collapses R1+R2 = 30; (az_a, n4, az_b) stays R3 = 30.
        assert_eq!(
            node_az_map
                .get(&NodeAzKey {
                    src_az: src_a_ref.clone(),
                    src_node: n1_ref.clone(),
                    dst_az: dst_b_ref.clone(),
                })
                .unwrap()
                .tcp
                .sum_bytes,
            30
        );
        assert_eq!(
            node_az_map
                .get(&NodeAzKey {
                    src_az: src_a_ref.clone(),
                    src_node: n4_ref.clone(),
                    dst_az: dst_b_ref.clone(),
                })
                .unwrap()
                .tcp
                .sum_bytes,
            30
        );

        // az-node (az_id): (az_a, n2, az_b) collapses R1+R3 = 40; (az_a, n3, az_b) stays R2 = 20.
        assert_eq!(
            az_node_map
                .get(&AzNodeKey {
                    src_az: src_a_ref.clone(),
                    dst_node: n2_ref.clone(),
                    dst_az: dst_b_ref.clone(),
                })
                .unwrap()
                .tcp
                .sum_bytes,
            40
        );
        assert_eq!(
            az_node_map
                .get(&AzNodeKey {
                    src_az: src_a_ref.clone(),
                    dst_node: n3_ref.clone(),
                    dst_az: dst_b_ref.clone(),
                })
                .unwrap()
                .tcp
                .sum_bytes,
            20
        );

        // az-az: all three entries collapse into a single (az_a, az_b) = 60.
        assert_eq!(
            az_az_map
                .get(&AzAzKey {
                    src_az: src_a_ref.clone(),
                    dst_az: dst_b_ref.clone(),
                })
                .unwrap()
                .tcp
                .sum_bytes,
            60
        );
    }

    #[test]
    fn zero_injection_and_keepalive_track_samples_across_windows() {
        let mut agg = Aggregator::new();
        let az_a = az("az-a");
        let az_b = az("az-b");
        let n1 = node("n1");
        let n2 = node("n2");

        agg.agg_root_start((0, 1));
        agg.update_node((0, 1), Side::A, az_a.clone(), n1.clone());
        agg.update_node((0, 1), Side::B, az_b.clone(), n2.clone());
        agg.add_tcp((0, 1), Direction::AtoB, tcp(5));

        let key = NodeNodeKey {
            src_az: agg.az_store.find(&az_a).unwrap(),
            src_node: agg.node_store.find(&n1).unwrap(),
            dst_az: agg.az_store.find(&az_b).unwrap(),
            dst_node: agg.node_store.find(&n2).unwrap(),
        };
        let entry = |agg: &Aggregator| -> (AllMetrics, bool) {
            let v = agg.node_node_store.find(&key).unwrap();
            let e = v.value(&agg.node_node_store).unwrap();
            (e.metrics.clone(), e.keepalive.is_some())
        };

        // Window 1: live data present -> emits, and keeps the entry alive.
        let (m1, keepalive1) = entry(&agg);
        assert_eq!(m1.tcp.sum_bytes, 5);
        assert!(m1.should_emit_any());
        assert!(keepalive1);
        agg.reset_after_emit();

        // Window 2: no new samples, but window 1 had them -> one injected
        // zero-valued emission, and the entry is still kept alive (this
        // window's now-zero counters haven't triggered the keepalive drop
        // yet, since the reset that inspects them hasn't run).
        let (m2, keepalive2) = entry(&agg);
        assert_eq!(m2.tcp.sum_bytes, 0);
        assert!(m2.tcp_prev_window_had_samples);
        assert!(m2.should_emit_any());
        assert!(keepalive2);
        agg.reset_after_emit();

        // Window 3: still no new samples -> the carried-forward flag has
        // been consumed, the entry stops emitting, and keepalive is dropped.
        let (m3, keepalive3) = entry(&agg);
        assert!(!m3.tcp_prev_window_had_samples);
        assert!(!m3.should_emit_any());
        assert!(!keepalive3);
    }

    #[test]
    fn metric_arriving_before_sides_are_resolved_is_dropped_and_counted() {
        let mut agg = Aggregator::new();

        // Entirely unknown root: never agg_root_start'd. `add_tcp` counts
        // this as both "missing root" and "before sides resolved" - the two
        // counters are not mutually exclusive in the ported code, since
        // `find_node_node_ref` bumps the former internally and `add_tcp`
        // unconditionally bumps the latter whenever no ref comes back.
        agg.add_tcp((0, 99), Direction::AtoB, tcp(1));
        assert_eq!(agg.events.missing_root_for_metric, 1);
        assert_eq!(agg.events.metric_before_sides_resolved, 1);

        // Root started, but only one side resolved so far: the root is
        // found, so `missing_root_for_metric` does not grow further, but
        // `metric_before_sides_resolved` still counts the drop.
        agg.agg_root_start((0, 1));
        agg.update_node((0, 1), Side::A, az("az-a"), node("n1"));
        agg.add_tcp((0, 1), Direction::AtoB, tcp(1));
        assert_eq!(agg.events.metric_before_sides_resolved, 2);
        assert_eq!(agg.events.missing_root_for_metric, 1);

        // Neither case created a node-node entry.
        assert!(agg.node_node_store.is_empty());
    }
}
