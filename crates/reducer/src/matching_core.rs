//! Rust matching core: reads the ingest->matching element queues, parses
//! render-generated wire messages, and drives a virtual clock over timeslots.
//!
//! Follows `aggregation_core`: `QueueHandler` owns the `ElementQueue`
//! instances built from `EqView` descriptors, the virtual clock, the batch
//! limits and the cooperative stop flag; this type owns the parser and the
//! message handler. Flow matching, enrichment and the downstream write side
//! land on top of this structure without changing the run loop.

use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use render_parser::Parser;

use crate::matching_message_handler::{Handler, MatchingMessageHandler, MatchingStats};
use crate::queue_handler::QueueHandler;
use encoder_ebpf_net_matching::hash::{matching_hash, MATCHING_HASH_SIZE};

/// Matching core: one instance per matching shard.
pub struct MatchingCore {
    queue_handler: QueueHandler,
    parser: Parser<Handler, fn(u32) -> u32>,
    shard: u32,
    stop: Arc<AtomicBool>,
    handler: Rc<MatchingMessageHandler>,
    stats: Arc<MatchingStats>,
}

impl MatchingCore {
    /// Builds a core over the ingest->matching queues described by
    /// `eq_views`, each entry being `(base_pointer, n_elems, buf_len)` of one
    /// contiguous element-queue storage region.
    pub fn new(eq_views: &[(usize, u32, u32)], shard: u32) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let queue_handler = QueueHandler::new_from_views(eq_views, stop.clone());

        // Parser keyed on the render-generated matching perfect hash.
        let hash_size = MATCHING_HASH_SIZE as usize;
        let mut parser: Parser<Handler, fn(u32) -> u32> = Parser::new(hash_size, matching_hash);

        let stats = Arc::new(MatchingStats::default());
        let handler = MatchingMessageHandler::new(&mut parser, stats.clone());

        Self {
            queue_handler,
            parser,
            shard,
            stop,
            handler,
            stats,
        }
    }

    /// Requests a cooperative stop of the run loop.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    /// Counters describing what this core has processed.
    pub fn stats(&self) -> &Arc<MatchingStats> {
        &self.stats
    }

    /// Reads and dispatches messages until [`MatchingCore::stop`] is called.
    pub fn run(&mut self) {
        if self.queue_handler.is_empty() {
            return;
        }

        // Disjoint field borrows: the callbacks read the parser and handler
        // while the queue handler drives the loop mutably.
        let shard = self.shard;
        let parser = &self.parser;
        let stats = self.stats.clone();
        let timeslot_handler = self.handler.clone();

        self.queue_handler.run(
            move |queue_idx, bytes| match parser.handle(bytes) {
                Ok(ok) => (ok.value)(shard, queue_idx, ok.timestamp, ok.message),
                Err(e) => {
                    stats.record_parse_error();
                    println!(
                        "matching[shard={}] eq={} parse_error={:?}",
                        shard, queue_idx, e
                    );
                }
            },
            move |window_end_ns| timeslot_handler.on_timeslot_complete(window_end_ns),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::thread;
    use std::time::{Duration, Instant};

    use element_queue::MemElementQueueStorage;
    use encoder_ebpf_net_matching::wire_messages;
    use render_parser::{MessageMetadata, Size};

    const N_ELEMS: u32 = 64;
    const BUF_LEN: u32 = 4096;
    const TIMESLOT_NS: u64 = 30_000_000_000;
    const DYNAMIC_BODY_LEN: u16 = 16;

    /// Builds one queue element the way the render-generated encoders lay it
    /// out: native-endian timestamp, then the message body starting with
    /// `_rpc_id` (and `_len` for dynamic messages).
    fn element(md: MessageMetadata, timestamp: u64) -> Vec<u8> {
        let body_len = match md.size() {
            Size::Fixed(n) => n,
            Size::Dynamic => DYNAMIC_BODY_LEN as usize,
        };

        let mut buf = Vec::with_capacity(8 + body_len);
        buf.extend_from_slice(&timestamp.to_ne_bytes());
        buf.resize(8 + body_len, 0);
        buf[8..10].copy_from_slice(&md.rpc_id().to_ne_bytes());
        if md.size() == Size::Dynamic {
            buf[10..12].copy_from_slice(&DYNAMIC_BODY_LEN.to_ne_bytes());
        }
        buf
    }

    /// An element with an rpc id no matching handler is registered for.
    fn unregistered_element(timestamp: u64) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&timestamp.to_ne_bytes());
        buf.extend_from_slice(&9999_u16.to_ne_bytes());
        buf.resize(24, 0);
        buf
    }

    fn write_elements(storage: &MemElementQueueStorage, elements: &[Vec<u8>]) {
        let mut queue = storage.make_queue().expect("writer queue");
        let mut batch = queue.start_write();
        for bytes in elements {
            batch
                .write(bytes.len() as u32)
                .expect("queue space")
                .copy_from_slice(bytes);
        }
        let _ = batch.finish();
    }

    fn views(storage: &MemElementQueueStorage) -> Vec<(usize, u32, u32)> {
        vec![(storage.data_ptr() as usize, N_ELEMS, BUF_LEN)]
    }

    /// Stops the core once `done` holds, or after a timeout. Returns whether
    /// `done` was observed, so tests fail loudly instead of hanging.
    fn stop_when(
        core: &MatchingCore,
        done: impl Fn(&MatchingStats) -> bool + Send + 'static,
    ) -> thread::JoinHandle<bool> {
        let stop = core.stop.clone();
        let stats = core.stats.clone();
        thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut satisfied = false;
            while Instant::now() < deadline {
                if done(&stats) {
                    satisfied = true;
                    break;
                }
                thread::sleep(Duration::from_millis(1));
            }
            stop.store(true, Ordering::Relaxed);
            satisfied
        })
    }

    /// The full read loop drains a synthetic queue and dispatches every
    /// registered message type, fixed- and dynamic-sized alike.
    #[test]
    fn read_loop_dispatches_registered_messages() {
        let storage = MemElementQueueStorage::new(N_ELEMS, BUF_LEN);
        let elements = vec![
            element(wire_messages::jb_matching__flow_start::metadata(), 1_000),
            element(wire_messages::jb_matching__tcp_update::metadata(), 2_000),
            element(wire_messages::jb_matching__k8s_pod_start::metadata(), 3_000),
            element(
                wire_messages::jb_matching__set_pod_detail::metadata(),
                4_000,
            ),
            element(wire_messages::jb_matching__pulse::metadata(), 5_000),
        ];
        write_elements(&storage, &elements);

        let mut core = MatchingCore::new(&views(&storage), 3);
        let expected = elements.len() as u64;
        let stopper = stop_when(&core, move |s| s.messages_handled() >= expected);
        core.run();

        assert!(stopper.join().unwrap(), "core did not drain the queue");
        assert_eq!(core.stats().messages_handled(), expected);
        assert_eq!(core.stats().parse_errors(), 0);
    }

    /// Crossing a timeslot boundary completes the timeslot and reports its
    /// aligned end timestamp, then processing continues in the new slot.
    #[test]
    fn timeslot_completes_when_clock_advances() {
        let storage = MemElementQueueStorage::new(N_ELEMS, BUF_LEN);
        let first_ts = 1_000_000_000;
        let elements = vec![
            element(wire_messages::jb_matching__flow_start::metadata(), first_ts),
            element(
                wire_messages::jb_matching__flow_end::metadata(),
                first_ts + 2 * TIMESLOT_NS,
            ),
        ];
        write_elements(&storage, &elements);

        let mut core = MatchingCore::new(&views(&storage), 0);
        let stopper = stop_when(&core, |s| {
            s.messages_handled() >= 2 && s.timeslots_completed() >= 1
        });
        core.run();

        assert!(stopper.join().unwrap(), "timeslot did not complete");
        assert_eq!(core.stats().messages_handled(), 2);

        // The reported boundary is aligned with the same approximate divider
        // the clock uses, so it lands near — not exactly on — 30s.
        let window_end = core.stats().last_timeslot_end_ns();
        let drift = window_end.abs_diff(TIMESLOT_NS);
        assert!(
            drift < TIMESLOT_NS / 100,
            "window end {window_end} is not within 1% of the {TIMESLOT_NS}ns boundary"
        );
    }

    /// An unparseable element is counted and drained; the loop keeps going and
    /// still dispatches the messages behind it.
    #[test]
    fn unparseable_element_is_counted_and_skipped() {
        let storage = MemElementQueueStorage::new(N_ELEMS, BUF_LEN);
        let elements = vec![
            unregistered_element(1_000),
            element(wire_messages::jb_matching__agent_info::metadata(), 2_000),
        ];
        write_elements(&storage, &elements);

        let mut core = MatchingCore::new(&views(&storage), 0);
        let stopper = stop_when(&core, |s| {
            s.parse_errors() >= 1 && s.messages_handled() >= 1
        });
        core.run();

        assert!(
            stopper.join().unwrap(),
            "core did not recover from the error"
        );
        assert_eq!(core.stats().parse_errors(), 1);
        assert_eq!(core.stats().messages_handled(), 1);
    }

    /// Messages spread over several queues are all dispatched.
    #[test]
    fn read_loop_covers_every_queue() {
        let first = MemElementQueueStorage::new(N_ELEMS, BUF_LEN);
        let second = MemElementQueueStorage::new(N_ELEMS, BUF_LEN);
        write_elements(
            &first,
            &[element(
                wire_messages::jb_matching__socket_info::metadata(),
                1_000,
            )],
        );
        write_elements(
            &second,
            &[element(
                wire_messages::jb_matching__container_info::metadata(),
                1_000,
            )],
        );

        let eq_views = vec![
            (first.data_ptr() as usize, N_ELEMS, BUF_LEN),
            (second.data_ptr() as usize, N_ELEMS, BUF_LEN),
        ];
        let mut core = MatchingCore::new(&eq_views, 1);
        let stopper = stop_when(&core, |s| s.messages_handled() >= 2);
        core.run();

        assert!(stopper.join().unwrap(), "not all queues were drained");
        assert_eq!(core.stats().messages_handled(), 2);
    }

    /// With no queues there is nothing to read, so `run` returns instead of
    /// spinning until stopped.
    #[test]
    fn run_without_queues_returns_immediately() {
        let mut core = MatchingCore::new(&[], 0);
        core.run();
        assert_eq!(core.stats().messages_handled(), 0);
    }
}
