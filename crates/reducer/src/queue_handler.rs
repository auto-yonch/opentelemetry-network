use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use element_queue::ElementQueue;
use timeslot::virtual_clock::VirtualClock;
use timeslot::FastDiv;

// Keep batch size reasonable to avoid starving other work
const K_MAX_RPC_BATCH_PER_QUEUE: usize = 10_000;

/// Drives reading from element queues and advancing a virtual clock, invoking
/// user-provided callbacks for each message and at the end of each timeslot.
pub struct QueueHandler {
    queues: Vec<ElementQueue>,
    clock: VirtualClock,
    timeslot_div: FastDiv,
    stop: Arc<AtomicBool>,
    last_processed_ts: u64,
}

impl QueueHandler {
    /// Construct from contiguous element-queue descriptors and a shared stop flag.
    pub fn new_from_views(eq_views: &[(usize, u32, u32)], stop: Arc<AtomicBool>) -> Self {
        // Build queues from contiguous storage descriptors
        let mut queues = Vec::with_capacity(eq_views.len());
        for (data, n_elems, buf_len) in eq_views.iter().cloned() {
            let ptr = data as *mut u8;
            let q = unsafe { ElementQueue::new_from_contiguous(n_elems, buf_len, ptr) }
                .expect("failed to create ElementQueue from contiguous storage");
            queues.push(q);
        }

        // Virtual clock configured with 30s timeslots (approximate)
        let timeslot_div = FastDiv::new(30e9_f64, 16);
        let mut clock = VirtualClock::new(timeslot_div.clone());
        clock.add_inputs(queues.len());

        Self {
            queues,
            clock,
            timeslot_div,
            stop,
            last_processed_ts: 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.queues.is_empty()
    }

    /// Run the queue handling loop until `stop` is set.
    ///
    /// - `handle_message(queue_idx, bytes)` is invoked for each element that
    ///   falls into the current timeslot.
    /// - `handle_timeslot_end(window_end_ns)` is invoked every time the clock
    ///   advances past the current timeslot; `window_end_ns` is aligned to the
    ///   configured timeslot size using an approximate divider.
    pub fn run<HM, HT>(&mut self, mut handle_message: HM, mut handle_timeslot_end: HT)
    where
        HM: FnMut(usize, &[u8]),
        HT: FnMut(u64),
    {
        if self.queues.is_empty() {
            return;
        }

        let mut next_idx: usize = 0;
        let time_budget = Duration::from_millis(20);

        while !self.stop.load(Ordering::Relaxed) {
            let start_cycle = Instant::now();

            for _ in 0..self.queues.len() {
                let i = next_idx;
                next_idx = (next_idx + 1) % self.queues.len();

                if !self.clock.can_update(i) {
                    continue;
                }

                // RAII read guard
                let rb = self.queues[i].start_read();
                let mut handled_in_queue = 0usize;

                while handled_in_queue < K_MAX_RPC_BATCH_PER_QUEUE
                    && self.clock.can_update(i)
                    && rb.peek_len().is_ok()
                {
                    // Peek timestamp (native-endian u64 at start of element)
                    let ts = match rb.peek_value::<u64>() {
                        Ok(v) => v,
                        Err(_e) => {
                            // Drain malformed element and continue
                            let _ = rb.read();
                            continue;
                        }
                    };

                    // Update clock for this input
                    match self.clock.update(i, ts) {
                        Ok(()) => {}
                        Err(timeslot::virtual_clock::UpdateError::PastTimeslot) => {
                            // Drain and continue
                            let _ = rb.read();
                            continue;
                        }
                        Err(timeslot::virtual_clock::UpdateError::NotPermitted) => {
                            break;
                        }
                    }

                    if self.clock.is_current(i) {
                        match rb.read() {
                            Ok(bytes) => {
                                handle_message(i, bytes);
                                // Track last processed timestamp while in current slot
                                self.last_processed_ts = ts;
                            }
                            Err(_e) => break,
                        }
                        handled_in_queue += 1;
                    }

                    if start_cycle.elapsed() >= time_budget {
                        break; // yield and rotate queues
                    }
                }

                // Publish read heads
                let _ = rb.finish();
            }

            if self.clock.advance() {
                // Compute the window end timestamp aligned to the 30s slot
                let slot_ns = self.timeslot_div.estimated_reciprocal().round() as u64;
                let rem = self.timeslot_div.remainder(self.last_processed_ts, slot_ns);
                let window_end_ns = self
                    .last_processed_ts
                    .saturating_sub(rem)
                    .saturating_add(slot_ns);
                handle_timeslot_end(window_end_ns);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use element_queue::MemElementQueueStorage;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// Pins the configured per-pass batch cap. This constant bounds how many
    /// elements a single queue can have dispatched within one round-robin
    /// pass (see the inner `while` loop in `run`); a change here is a
    /// deliberate behavior change, not a refactor.
    #[test]
    fn k_max_rpc_batch_per_queue_is_10_000() {
        assert_eq!(K_MAX_RPC_BATCH_PER_QUEUE, 10_000);
    }

    /// slot_ns rounding + window alignment: `handle_timeslot_end` fires with
    /// a `window_end_ns` computed from the *last delivered* timestamp,
    /// rounded down to the configured ~30s slot boundary and then bumped one
    /// slot forward - mirroring the exact formula in `run` so a regression in
    /// either side of the duplicated arithmetic fails the test.
    #[test]
    fn window_end_ns_aligns_to_slot_using_last_processed_timestamp() {
        let storage = MemElementQueueStorage::new(8, 4096);
        let t0: u64 = 1_000_000_000; // 1s into the run
        let boundary_ts: u64 = t0 + 100_000_000_000; // comfortably >1 slot ahead
        {
            let mut q = storage.make_queue().unwrap();
            let mut wb = q.start_write();
            wb.write(8).unwrap().copy_from_slice(&t0.to_ne_bytes());
            wb.write(8)
                .unwrap()
                .copy_from_slice(&boundary_ts.to_ne_bytes());
            let _ = wb.finish();
        }

        let stop = Arc::new(AtomicBool::new(false));
        let eq_views = [(
            storage.data_ptr() as usize,
            storage.n_elems(),
            storage.buf_len(),
        )];
        let mut handler = QueueHandler::new_from_views(&eq_views, stop.clone());

        let delivered: Rc<RefCell<Vec<u64>>> = Rc::new(RefCell::new(Vec::new()));
        let window_ends: Rc<RefCell<Vec<u64>>> = Rc::new(RefCell::new(Vec::new()));
        let d2 = delivered.clone();
        let w2 = window_ends.clone();
        let stop2 = stop.clone();

        handler.run(
            move |_idx, bytes| {
                let mut b = [0u8; 8];
                b.copy_from_slice(&bytes[..8]);
                d2.borrow_mut().push(u64::from_ne_bytes(b));
            },
            move |window_end_ns| {
                w2.borrow_mut().push(window_end_ns);
                stop2.store(true, Ordering::Relaxed);
            },
        );

        // Only the priming message (t0) is ever in the current slot; the far
        // boundary message just triggers the advance and is left unread.
        assert_eq!(*delivered.borrow(), vec![t0]);
        assert_eq!(window_ends.borrow().len(), 1);

        let slot_div = FastDiv::new(30e9_f64, 16);
        let slot_ns = slot_div.estimated_reciprocal().round() as u64;
        let rem = slot_div.remainder(t0, slot_ns);
        let expected = t0.saturating_sub(rem).saturating_add(slot_ns);
        assert_eq!(window_ends.borrow()[0], expected);
    }

    /// An element too short to hold a timestamp is silently drained (never
    /// delivered, never crashes) and the queue continues on to the next
    /// valid element.
    #[test]
    fn malformed_short_element_is_drained_and_skipped() {
        let storage = MemElementQueueStorage::new(8, 4096);
        let ts: u64 = 5_000_000_000;
        {
            let mut q = storage.make_queue().unwrap();
            let mut wb = q.start_write();
            // Too short to hold a u64 timestamp.
            wb.write(3).unwrap().copy_from_slice(&[0xAA, 0xBB, 0xCC]);
            wb.write(8).unwrap().copy_from_slice(&ts.to_ne_bytes());
            let _ = wb.finish();
        }

        let stop = Arc::new(AtomicBool::new(false));
        let eq_views = [(
            storage.data_ptr() as usize,
            storage.n_elems(),
            storage.buf_len(),
        )];
        let mut handler = QueueHandler::new_from_views(&eq_views, stop.clone());

        let delivered: Rc<RefCell<Vec<Vec<u8>>>> = Rc::new(RefCell::new(Vec::new()));
        let d2 = delivered.clone();
        let stop2 = stop.clone();

        handler.run(
            move |_idx, bytes| {
                d2.borrow_mut().push(bytes.to_vec());
                stop2.store(true, Ordering::Relaxed);
            },
            |_window_end_ns| {},
        );

        assert_eq!(delivered.borrow().len(), 1);
        assert_eq!(&delivered.borrow()[0][..], &ts.to_ne_bytes()[..]);
    }

    /// Once the virtual clock has advanced past a message's timeslot, a
    /// later-queued element whose timestamp maps to an *earlier* timeslot
    /// hits the `PastTimeslot` branch and is drained rather than delivered or
    /// causing a panic.
    #[test]
    fn stale_timestamp_after_advance_is_drained_via_past_timeslot() {
        let storage = MemElementQueueStorage::new(8, 4096);
        let t0: u64 = 1_000_000_000;
        let boundary_ts: u64 = t0 + 100_000_000_000; // moves the input forward
        let stale_ts: u64 = t0; // arrives after the advance, maps to an earlier slot
        {
            let mut q = storage.make_queue().unwrap();
            let mut wb = q.start_write();
            wb.write(8).unwrap().copy_from_slice(&t0.to_ne_bytes());
            wb.write(8)
                .unwrap()
                .copy_from_slice(&boundary_ts.to_ne_bytes());
            wb.write(8)
                .unwrap()
                .copy_from_slice(&stale_ts.to_ne_bytes());
            let _ = wb.finish();
        }

        let stop = Arc::new(AtomicBool::new(false));
        let eq_views = [(
            storage.data_ptr() as usize,
            storage.n_elems(),
            storage.buf_len(),
        )];
        let mut handler = QueueHandler::new_from_views(&eq_views, stop.clone());

        let delivered: Rc<RefCell<Vec<u64>>> = Rc::new(RefCell::new(Vec::new()));
        let d2 = delivered.clone();
        let stop2 = stop.clone();

        handler.run(
            move |_idx, bytes| {
                let mut b = [0u8; 8];
                b.copy_from_slice(&bytes[..8]);
                d2.borrow_mut().push(u64::from_ne_bytes(b));
                if d2.borrow().len() == 2 {
                    // t0 then boundary_ts have both been delivered; the stale
                    // element is drained within this same pass before the
                    // outer loop rechecks `stop`.
                    stop2.store(true, Ordering::Relaxed);
                }
            },
            |_window_end_ns| {},
        );

        // The stale element is never delivered - only t0 and boundary_ts are.
        assert_eq!(*delivered.borrow(), vec![t0, boundary_ts]);
    }

    /// Round-robin: with two queues each holding a message in the same
    /// timeslot, both are delivered within a single outer pass rather than
    /// one queue starving the other.
    #[test]
    fn round_robin_delivers_from_both_queues_within_one_pass() {
        let storage_a = MemElementQueueStorage::new(8, 4096);
        let storage_b = MemElementQueueStorage::new(8, 4096);
        let ts: u64 = 2_000_000_000;
        for storage in [&storage_a, &storage_b] {
            let mut q = storage.make_queue().unwrap();
            let mut wb = q.start_write();
            wb.write(8).unwrap().copy_from_slice(&ts.to_ne_bytes());
            let _ = wb.finish();
        }

        let stop = Arc::new(AtomicBool::new(false));
        let eq_views = [
            (
                storage_a.data_ptr() as usize,
                storage_a.n_elems(),
                storage_a.buf_len(),
            ),
            (
                storage_b.data_ptr() as usize,
                storage_b.n_elems(),
                storage_b.buf_len(),
            ),
        ];
        let mut handler = QueueHandler::new_from_views(&eq_views, stop.clone());

        let delivered: Rc<RefCell<Vec<usize>>> = Rc::new(RefCell::new(Vec::new()));
        let d2 = delivered.clone();
        let stop2 = stop.clone();
        handler.run(
            move |queue_idx, _bytes| {
                d2.borrow_mut().push(queue_idx);
                if d2.borrow().len() == 2 {
                    stop2.store(true, Ordering::Relaxed);
                }
            },
            |_| {},
        );

        let delivered = delivered.borrow();
        assert_eq!(delivered.len(), 2);
        assert!(delivered.contains(&0));
        assert!(delivered.contains(&1));
    }

    /// A backlog larger than `K_MAX_RPC_BATCH_PER_QUEUE` is fully drained
    /// across however many passes batching requires, with every element
    /// delivered exactly once and in FIFO order - no loss, no duplication, no
    /// reordering at the batch-cap boundary. (The public `run` callback
    /// surface cannot directly observe the per-pass split itself; that is
    /// pinned separately by the constant test above.)
    #[test]
    fn large_backlog_exceeding_batch_cap_is_fully_drained_without_loss_or_reorder() {
        const N: usize = K_MAX_RPC_BATCH_PER_QUEUE + 5;
        // ElementQueue requires both dimensions to be a power of two.
        let n_elems = ((N + 10) as u32).next_power_of_two();
        let buf_len = ((N * 16) as u32).next_power_of_two();
        let storage = MemElementQueueStorage::new(n_elems, buf_len);
        let base_ts: u64 = 1_000_000_000; // identical ts: stays within one timeslot
        {
            let mut q = storage.make_queue().unwrap();
            let mut wb = q.start_write();
            for i in 0..N {
                let mut elem = [0u8; 16];
                elem[0..8].copy_from_slice(&base_ts.to_ne_bytes());
                elem[8..16].copy_from_slice(&(i as u64).to_ne_bytes());
                wb.write(16).unwrap().copy_from_slice(&elem);
            }
            let _ = wb.finish();
        }

        let stop = Arc::new(AtomicBool::new(false));
        let eq_views = [(
            storage.data_ptr() as usize,
            storage.n_elems(),
            storage.buf_len(),
        )];
        let mut handler = QueueHandler::new_from_views(&eq_views, stop.clone());

        let delivered: Rc<RefCell<Vec<u64>>> = Rc::new(RefCell::new(Vec::new()));
        let d2 = delivered.clone();
        let stop2 = stop.clone();
        handler.run(
            move |_idx, bytes| {
                let mut b = [0u8; 8];
                b.copy_from_slice(&bytes[8..16]);
                d2.borrow_mut().push(u64::from_ne_bytes(b));
                if d2.borrow().len() == N {
                    stop2.store(true, Ordering::Relaxed);
                }
            },
            |_| {},
        );

        let expected: Vec<u64> = (0..N as u64).collect();
        assert_eq!(*delivered.borrow(), expected);
    }
}
