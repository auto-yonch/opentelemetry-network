//! Message registration and dispatch for the matching core.
//!
//! Mirrors `aggregation_message_handler` in shape: the handler owns the
//! matching-side state and registers one closure per render-generated wire
//! message with the parser. In this skeleton the closures only account for
//! what arrived — flow matching and enrichment land in the flow-span port and
//! slot into the `on_*` methods below without touching the run loop.

use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use render_parser::Parser;

use encoder_ebpf_net_matching::wire_messages;

/// Parser value type: dispatch closures registered per RPC id.
///
/// Arguments are `(shard, queue_index, timestamp_ns, message_bytes)`, matching
/// the aggregation core's handler signature.
pub type Handler = Box<dyn Fn(u32, usize, u64, &[u8]) + 'static>;

/// Counters describing what the matching core observed.
///
/// Shared behind an `Arc` so a supervising thread (and the unit tests) can
/// observe progress while the core's own loop runs single-threaded.
#[derive(Debug, Default)]
pub struct MatchingStats {
    messages_handled: AtomicU64,
    parse_errors: AtomicU64,
    timeslots_completed: AtomicU64,
    last_timeslot_end_ns: AtomicU64,
}

impl MatchingStats {
    /// Number of wire messages dispatched to a registered handler.
    pub fn messages_handled(&self) -> u64 {
        self.messages_handled.load(Ordering::Relaxed)
    }

    /// Number of queue elements the parser rejected.
    pub fn parse_errors(&self) -> u64 {
        self.parse_errors.load(Ordering::Relaxed)
    }

    /// Number of times the virtual clock advanced past a timeslot.
    pub fn timeslots_completed(&self) -> u64 {
        self.timeslots_completed.load(Ordering::Relaxed)
    }

    /// End timestamp of the most recently completed timeslot.
    pub fn last_timeslot_end_ns(&self) -> u64 {
        self.last_timeslot_end_ns.load(Ordering::Relaxed)
    }

    pub(crate) fn record_parse_error(&self) {
        self.parse_errors.fetch_add(1, Ordering::Relaxed);
    }
}

/// Owns matching-side state and the closures registered with the parser.
pub struct MatchingMessageHandler {
    stats: Arc<MatchingStats>,
}

/// Registers one dispatch closure per render-generated wire message.
///
/// A collision is a build-time defect in the render-generated perfect hash for
/// this package, not a runtime condition, so it fails loudly here.
macro_rules! register_messages {
    ($parser:expr, $handler:expr, [$($msg:ident),+ $(,)?]) => {
        $({
            let h: Rc<MatchingMessageHandler> = $handler.clone();
            $parser
                .add_message(
                    wire_messages::$msg::metadata(),
                    Box::new(
                        move |_shard: u32, queue_idx: usize, timestamp: u64, buf: &[u8]| {
                            h.on_message(queue_idx, timestamp, buf)
                        },
                    ) as Handler,
                )
                .unwrap_or_else(|e| {
                    panic!(
                        "matching perfect hash collision registering {}: existing_key={}",
                        stringify!($msg),
                        e.existing_key
                    )
                });
        })+
    };
}

impl MatchingMessageHandler {
    /// Creates the handler and registers every matching wire message with
    /// `parser`.
    pub fn new(
        parser: &mut Parser<Handler, fn(u32) -> u32>,
        stats: Arc<MatchingStats>,
    ) -> Rc<Self> {
        let rc = Rc::new(Self { stats });

        register_messages!(
            parser,
            rc,
            [
                jb_matching__flow_start,
                jb_matching__flow_end,
                jb_matching__agent_info,
                jb_matching__task_info,
                jb_matching__socket_info,
                jb_matching__k8s_info,
                jb_matching__tcp_update,
                jb_matching__udp_update,
                jb_matching__http_update,
                jb_matching__dns_update,
                jb_matching__container_info,
                jb_matching__service_info,
                jb_matching__aws_enrichment_start,
                jb_matching__aws_enrichment_end,
                jb_matching__aws_enrichment,
                jb_matching__k8s_pod_start,
                jb_matching__k8s_pod_end,
                jb_matching__set_pod_detail,
                jb_matching__k8s_container_start,
                jb_matching__k8s_container_end,
                jb_matching__set_container_pod,
                jb_matching__pulse,
            ]
        );

        rc
    }

    /// Invoked for every successfully parsed message.
    ///
    /// The flow-span port replaces this single sink with per-message handlers;
    /// the registration list and the run loop stay as they are.
    fn on_message(&self, _queue_idx: usize, _timestamp: u64, _buf: &[u8]) {
        self.stats.messages_handled.fetch_add(1, Ordering::Relaxed);
    }

    /// Invoked when the virtual clock advances past a timeslot.
    ///
    /// The C++ shell does its flow-metric send to aggregation here
    /// (`MatchingCore::on_timeslot_complete`); the Rust equivalent lands with
    /// the flow-span port.
    pub fn on_timeslot_complete(&self, window_end_ns: u64) {
        self.stats
            .timeslots_completed
            .fetch_add(1, Ordering::Relaxed);
        self.stats
            .last_timeslot_end_ns
            .store(window_end_ns, Ordering::Relaxed);
    }
}
