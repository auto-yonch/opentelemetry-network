//! Message decoding and dispatch into the Aggregator using a handler struct.

use std::cell::RefCell;
use std::rc::Rc;

use render_parser::Parser;

use crate::aggregator::{AggRootKey, Aggregator, Az, Direction, Node, Side};
use crate::metrics::{DnsMetrics, HttpMetrics, TcpMetrics, UdpMetrics};
use encoder_ebpf_net_aggregation::parsed_message;
use encoder_ebpf_net_aggregation::wire_messages;

type Handler = Box<dyn Fn(u32, usize, u64, &[u8]) + 'static>;

#[derive(Clone)]
pub struct AggregationMessageHandler {
    agg: Rc<RefCell<Aggregator>>,
}

impl AggregationMessageHandler {
    pub fn new(
        parser: &mut Parser<Handler, fn(u32) -> u32>,
        agg: Rc<RefCell<Aggregator>>,
    ) -> Rc<Self> {
        let rc = Rc::new(Self { agg });

        // Register closures that capture Rc<Self>
        {
            let h = rc.clone();
            let _ = parser.add_message(
                wire_messages::jb_aggregation__agg_root_start::metadata(),
                Box::new(move |_shard, q, _ts, buf| h.on_agg_root_start(q, buf)),
            );
        }
        {
            let h = rc.clone();
            let _ = parser.add_message(
                wire_messages::jb_aggregation__agg_root_end::metadata(),
                Box::new(move |_shard, q, _ts, buf| h.on_agg_root_end(q, buf)),
            );
        }
        {
            let h = rc.clone();
            let _ = parser.add_message(
                wire_messages::jb_aggregation__update_node::metadata(),
                Box::new(move |_shard, q, _ts, buf| h.on_update_node(q, buf)),
            );
        }
        {
            let h = rc.clone();
            let _ = parser.add_message(
                wire_messages::jb_aggregation__update_tcp_metrics::metadata(),
                Box::new(move |_shard, q, _ts, buf| h.on_update_tcp(q, buf)),
            );
        }
        {
            let h = rc.clone();
            let _ = parser.add_message(
                wire_messages::jb_aggregation__update_udp_metrics::metadata(),
                Box::new(move |_shard, q, _ts, buf| h.on_update_udp(q, buf)),
            );
        }
        {
            let h = rc.clone();
            let _ = parser.add_message(
                wire_messages::jb_aggregation__update_http_metrics::metadata(),
                Box::new(move |_shard, q, _ts, buf| h.on_update_http(q, buf)),
            );
        }
        {
            let h = rc.clone();
            let _ = parser.add_message(
                wire_messages::jb_aggregation__update_dns_metrics::metadata(),
                Box::new(move |_shard, q, _ts, buf| h.on_update_dns(q, buf)),
            );
        }
        {
            let h = rc.clone();
            let _ = parser.add_message(
                wire_messages::jb_aggregation__pulse::metadata(),
                Box::new(move |_shard, _q, _ts, buf| h.on_pulse(buf)),
            );
        }

        rc
    }

    fn on_agg_root_start(&self, queue_idx: usize, buf: &[u8]) {
        match parsed_message::agg_root_start::decode(buf) {
            Ok(msg) => {
                let key: AggRootKey = (queue_idx, msg._ref);
                self.agg.borrow_mut().agg_root_start(key);
            }
            Err(_e) => self
                .agg
                .borrow_mut()
                .events
                .inc_decode_error_agg_root_start(),
        }
    }

    fn on_agg_root_end(&self, queue_idx: usize, buf: &[u8]) {
        match parsed_message::agg_root_end::decode(buf) {
            Ok(msg) => {
                let key: AggRootKey = (queue_idx, msg._ref);
                self.agg.borrow_mut().agg_root_end(key);
            }
            Err(_e) => self.agg.borrow_mut().events.inc_decode_error_agg_root_end(),
        }
    }

    fn on_update_node(&self, queue_idx: usize, buf: &[u8]) {
        match parsed_message::update_node::decode(buf) {
            Ok(msg) => {
                let key: AggRootKey = (queue_idx, msg._ref);
                let az = Az {
                    az: msg.az.to_string(),
                    role: msg.role.to_string(),
                    version: msg.version.to_string(),
                    env: msg.env.to_string(),
                    ns: msg.ns.to_string(),
                    node_type: msg.node_type as u8,
                    process: msg.process.to_string(),
                    container: msg.container.to_string(),
                    role_uid: msg.role_uid.to_string(),
                };
                let node = Node {
                    id: msg.id.to_string(),
                    address: msg.address.to_string(),
                    pod_name: msg.pod_name.to_string(),
                };
                self.agg.borrow_mut().update_node(
                    key,
                    if msg.side == 0 { Side::A } else { Side::B },
                    az,
                    node,
                );
            }
            Err(_e) => self.agg.borrow_mut().events.inc_decode_error_update_node(),
        }
    }

    fn on_update_tcp(&self, queue_idx: usize, buf: &[u8]) {
        match parsed_message::update_tcp_metrics::decode(buf) {
            Ok(msg) => {
                let key: AggRootKey = (queue_idx, msg._ref);
                let m = TcpMetrics {
                    active_sockets: msg.active_sockets as u64,
                    sum_bytes: msg.sum_bytes as u64,
                    sum_srtt: msg.sum_srtt as u64,
                    sum_delivered: msg.sum_delivered as u64,
                    sum_retrans: msg.sum_retrans as u64,
                    active_rtts: msg.active_rtts as u64,
                    syn_timeouts: msg.syn_timeouts as u64,
                    new_sockets: msg.new_sockets as u64,
                    tcp_resets: msg.tcp_resets as u64,
                };
                let dir = if msg.direction == 0 {
                    Direction::AtoB
                } else {
                    Direction::BtoA
                };
                self.agg.borrow_mut().add_tcp(key, dir, m);
            }
            Err(_e) => self.agg.borrow_mut().events.inc_decode_error_update_tcp(),
        }
    }

    fn on_update_udp(&self, queue_idx: usize, buf: &[u8]) {
        match parsed_message::update_udp_metrics::decode(buf) {
            Ok(msg) => {
                let key: AggRootKey = (queue_idx, msg._ref);
                let m = UdpMetrics {
                    active_sockets: msg.active_sockets as u64,
                    bytes: msg.bytes as u64,
                    addr_changes: msg.addr_changes as u64,
                    packets: msg.packets as u64,
                    drops: msg.drops as u64,
                };
                let dir = if msg.direction == 0 {
                    Direction::AtoB
                } else {
                    Direction::BtoA
                };
                self.agg.borrow_mut().add_udp(key, dir, m);
            }
            Err(_e) => self.agg.borrow_mut().events.inc_decode_error_update_udp(),
        }
    }

    fn on_update_http(&self, queue_idx: usize, buf: &[u8]) {
        match parsed_message::update_http_metrics::decode(buf) {
            Ok(msg) => {
                let key: AggRootKey = (queue_idx, msg._ref);
                let m = HttpMetrics {
                    active_sockets: msg.active_sockets as u64,
                    sum_total_time_ns: msg.sum_total_time_ns as u64,
                    sum_processing_time_ns: msg.sum_processing_time_ns as u64,
                    sum_code_200: msg.sum_code_200 as u64,
                    sum_code_400: msg.sum_code_400 as u64,
                    sum_code_500: msg.sum_code_500 as u64,
                    sum_code_other: msg.sum_code_other as u64,
                };
                let dir = if msg.direction == 0 {
                    Direction::AtoB
                } else {
                    Direction::BtoA
                };
                self.agg.borrow_mut().add_http(key, dir, m);
            }
            Err(_e) => self.agg.borrow_mut().events.inc_decode_error_update_http(),
        }
    }

    fn on_update_dns(&self, queue_idx: usize, buf: &[u8]) {
        match parsed_message::update_dns_metrics::decode(buf) {
            Ok(msg) => {
                let key: AggRootKey = (queue_idx, msg._ref);
                let m = DnsMetrics {
                    active_sockets: msg.active_sockets as u64,
                    sum_total_time_ns: msg.sum_total_time_ns as u64,
                    sum_processing_time_ns: msg.sum_processing_time_ns as u64,
                    requests_a: msg.requests_a as u64,
                    requests_aaaa: msg.requests_aaaa as u64,
                    responses: msg.responses as u64,
                    timeouts: msg.timeouts as u64,
                };
                let dir = if msg.direction == 0 {
                    Direction::AtoB
                } else {
                    Direction::BtoA
                };
                self.agg.borrow_mut().add_dns(key, dir, m);
            }
            Err(_e) => self.agg.borrow_mut().events.inc_decode_error_update_dns(),
        }
    }

    fn on_pulse(&self, buf: &[u8]) {
        match parsed_message::pulse::decode(buf) {
            Ok(_msg) => {}
            Err(_e) => self.agg.borrow_mut().events.inc_decode_error_pulse(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ffi::c_char;
    use encoder_ebpf_net_aggregation::JbBlob;

    fn new_handler() -> AggregationMessageHandler {
        AggregationMessageHandler {
            agg: Rc::new(RefCell::new(Aggregator::new())),
        }
    }

    fn blob(s: &str) -> JbBlob {
        JbBlob {
            buf: s.as_ptr() as *const c_char,
            len: s.len() as u16,
        }
    }

    // The real parser consumes the leading 8-byte timestamp before handing
    // the remainder to a message handler - mirror that here.
    fn body(full: &[u8]) -> &[u8] {
        &full[8..]
    }

    fn encode_agg_root_start(r: u64) -> Vec<u8> {
        let mut buf = vec![0u8; 8 + 16];
        encoder_ebpf_net_aggregation::encoder::ebpf_net_aggregation_encode_agg_root_start(
            buf.as_mut_ptr(),
            buf.len() as u32,
            0,
            r,
        );
        buf
    }

    fn encode_agg_root_end(r: u64) -> Vec<u8> {
        let mut buf = vec![0u8; 8 + 16];
        encoder_ebpf_net_aggregation::encoder::ebpf_net_aggregation_encode_agg_root_end(
            buf.as_mut_ptr(),
            buf.len() as u32,
            0,
            r,
        );
        buf
    }

    fn encode_update_node(r: u64, side: u8, id: &str, az: &str, node_type: u8) -> Vec<u8> {
        // Only `id` and `az` carry real content in these tests; every other
        // string field is empty, so the consumed length is just the fixed
        // header plus those two.
        let consumed = 34 + id.len() + az.len();
        let mut buf = vec![0u8; 8 + consumed];
        encoder_ebpf_net_aggregation::encoder::ebpf_net_aggregation_encode_update_node(
            buf.as_mut_ptr(),
            buf.len() as u32,
            0,
            r,
            side,
            blob(id),
            blob(az),
            blob(""),
            blob(""),
            blob(""),
            blob(""),
            node_type,
            blob(""),
            blob(""),
            blob(""),
            blob(""),
            blob(""),
        );
        buf
    }

    fn encode_update_tcp(r: u64, direction: u8, sum_bytes: u64) -> Vec<u8> {
        let mut buf = vec![0u8; 8 + 60];
        encoder_ebpf_net_aggregation::encoder::ebpf_net_aggregation_encode_update_tcp_metrics(
            buf.as_mut_ptr(),
            buf.len() as u32,
            0,
            r,
            direction,
            1,
            0,
            sum_bytes,
            0,
            0,
            0,
            0,
            0,
            0,
        );
        buf
    }

    fn encode_update_udp(r: u64, direction: u8, bytes: u64) -> Vec<u8> {
        let mut buf = vec![0u8; 8 + 36];
        encoder_ebpf_net_aggregation::encoder::ebpf_net_aggregation_encode_update_udp_metrics(
            buf.as_mut_ptr(),
            buf.len() as u32,
            0,
            r,
            direction,
            1,
            0,
            0,
            bytes,
            0,
        );
        buf
    }

    fn encode_update_http(r: u64, direction: u8) -> Vec<u8> {
        let mut buf = vec![0u8; 8 + 48];
        encoder_ebpf_net_aggregation::encoder::ebpf_net_aggregation_encode_update_http_metrics(
            buf.as_mut_ptr(),
            buf.len() as u32,
            0,
            r,
            direction,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
        );
        buf
    }

    fn encode_update_dns(r: u64, direction: u8) -> Vec<u8> {
        let mut buf = vec![0u8; 8 + 48];
        encoder_ebpf_net_aggregation::encoder::ebpf_net_aggregation_encode_update_dns_metrics(
            buf.as_mut_ptr(),
            buf.len() as u32,
            0,
            r,
            direction,
            1,
            1,
            0,
            1,
            0,
            0,
            0,
        );
        buf
    }

    fn encode_pulse() -> Vec<u8> {
        let mut buf = vec![0u8; 8 + 2];
        encoder_ebpf_net_aggregation::encoder::ebpf_net_aggregation_encode_pulse(
            buf.as_mut_ptr(),
            buf.len() as u32,
            0,
        );
        buf
    }

    fn total_decode_errors(c: &crate::internal_events::Counters) -> u64 {
        c.decode_error_agg_root_start
            + c.decode_error_agg_root_end
            + c.decode_error_update_node
            + c.decode_error_update_tcp
            + c.decode_error_update_udp
            + c.decode_error_update_http
            + c.decode_error_update_dns
            + c.decode_error_pulse
    }

    #[test]
    fn malformed_buffer_increments_only_the_matching_decode_error_counter_per_message_type() {
        type Dispatch = fn(&AggregationMessageHandler, &[u8]);
        type CounterOf = fn(&crate::internal_events::Counters) -> u64;

        fn d_agg_root_start(h: &AggregationMessageHandler, b: &[u8]) {
            h.on_agg_root_start(0, b);
        }
        fn d_agg_root_end(h: &AggregationMessageHandler, b: &[u8]) {
            h.on_agg_root_end(0, b);
        }
        fn d_update_node(h: &AggregationMessageHandler, b: &[u8]) {
            h.on_update_node(0, b);
        }
        fn d_update_tcp(h: &AggregationMessageHandler, b: &[u8]) {
            h.on_update_tcp(0, b);
        }
        fn d_update_udp(h: &AggregationMessageHandler, b: &[u8]) {
            h.on_update_udp(0, b);
        }
        fn d_update_http(h: &AggregationMessageHandler, b: &[u8]) {
            h.on_update_http(0, b);
        }
        fn d_update_dns(h: &AggregationMessageHandler, b: &[u8]) {
            h.on_update_dns(0, b);
        }
        fn d_pulse(h: &AggregationMessageHandler, b: &[u8]) {
            h.on_pulse(b);
        }

        let cases: [(&str, Dispatch, CounterOf); 8] = [
            ("agg_root_start", d_agg_root_start, |c| {
                c.decode_error_agg_root_start
            }),
            ("agg_root_end", d_agg_root_end, |c| {
                c.decode_error_agg_root_end
            }),
            ("update_node", d_update_node, |c| c.decode_error_update_node),
            ("update_tcp", d_update_tcp, |c| c.decode_error_update_tcp),
            ("update_udp", d_update_udp, |c| c.decode_error_update_udp),
            ("update_http", d_update_http, |c| c.decode_error_update_http),
            ("update_dns", d_update_dns, |c| c.decode_error_update_dns),
            ("pulse", d_pulse, |c| c.decode_error_pulse),
        ];

        for (name, dispatch, counter_of) in cases {
            let handler = new_handler();
            // An empty buffer fails every message type's minimum-length check.
            dispatch(&handler, &[]);
            let events = handler.agg.borrow().events.clone();
            assert_eq!(
                counter_of(&events),
                1,
                "{name} should count its own decode error"
            );
            assert_eq!(
                total_decode_errors(&events),
                1,
                "{name} should not affect any other message type's decode-error counter"
            );
        }
    }

    #[test]
    fn successful_dispatch_wires_every_message_type_through_to_the_aggregator() {
        let handler = new_handler();
        let root: u64 = 7;

        let root_start = encode_agg_root_start(root);
        handler.on_agg_root_start(0, body(&root_start));

        let node_a = encode_update_node(root, 0, "node-a", "az-a", 0);
        handler.on_update_node(0, body(&node_a));
        let node_b = encode_update_node(root, 1, "node-b", "az-b", 0);
        handler.on_update_node(0, body(&node_b));

        let tcp = encode_update_tcp(root, 0, 100);
        handler.on_update_tcp(0, body(&tcp));
        let udp = encode_update_udp(root, 0, 50);
        handler.on_update_udp(0, body(&udp));
        let http = encode_update_http(root, 0);
        handler.on_update_http(0, body(&http));
        let dns = encode_update_dns(root, 0);
        handler.on_update_dns(0, body(&dns));

        let root_end = encode_agg_root_end(root);
        handler.on_agg_root_end(0, body(&root_end));

        let pulse = encode_pulse();
        handler.on_pulse(body(&pulse));

        let events = handler.agg.borrow().events.clone();
        assert_eq!(
            total_decode_errors(&events),
            0,
            "every wire message type should decode cleanly"
        );
        // Both sides were resolved before any metric arrived, and the root
        // was found every time - proving agg_root_start and both update_node
        // dispatches ran (and were wired correctly) before the four add_*
        // calls, all through real decode + dispatch, not direct Aggregator calls.
        assert_eq!(events.missing_root_for_metric, 0);
        assert_eq!(events.metric_before_sides_resolved, 0);
    }
}
