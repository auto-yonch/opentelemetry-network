//! Write side of the element queue: a producer handle over shared-memory
//! storage that drives the render-generated encoders.
//!
//! # Why this exists
//!
//! The read side of the reducer pipeline is already symmetric in Rust: a
//! [`ReadBatch`](crate::ReadBatch) hands element bytes to
//! `render_parser::Parser`, which uses the render-generated `hash` /
//! `wire_messages` / `parsed_message` code to decode a message. The write side
//! needs the mirror image: reserve an element of exactly the right length in
//! the ring buffer, then let a render-generated `..._encode_<message>` function
//! fill it with `timestamp + packed wire struct + dynamic payloads`.
//!
//! The generated encoders take a raw destination pointer plus a length, and
//! **assert that the length matches the encoded length exactly**. So the only
//! thing a caller can get wrong is the size, which is why sizing is a first
//! class type here ([`MessageSize`]) rather than an inline arithmetic
//! expression at every call site.
//!
//! # Layering
//!
//! This module deliberately knows nothing about any render package: it takes a
//! closure of the shape `FnOnce(*mut u8, u32)`. Because the generated encoders
//! are `pub extern "C" fn` items defined in Rust, calling one is *safe* Rust,
//! so filling an element requires no `unsafe` at the call site:
//!
//! ```ignore
//! use element_queue::{EqWriter, MessageSize};
//! use encoder_ebpf_net_matching::{encoder, wire_messages::FLOW_START_WIRE_SIZE};
//!
//! let size = MessageSize::fixed(FLOW_START_WIRE_SIZE as u32)?;
//! writer.write_message(size, |dest, dest_len| {
//!     encoder::ebpf_net_matching_encode_flow_start(
//!         dest, dest_len, timestamp, flow_ref, addr1, port1, addr2, port2,
//!     )
//! })?;
//! ```
//!
//! # Ring-buffer semantics
//!
//! Reserving and publishing reuses [`WriteBatch`](crate::WriteBatch) unchanged,
//! so producers here observe exactly the batching protocol the C++ readers
//! expect: element lengths land in the element ring, payload bytes land in the
//! data buffer (8-byte aligned, never split across the wrap point), and the
//! tails become visible to the consumer only on [`MessageBatch::commit`].
//! Dropping a batch without committing discards it.

use crate::layout::contig_size;
use crate::raw::{ElementQueue, EqError, WriteBatch};

/// Size in bytes of the native-endian timestamp that prefixes every element.
pub const TIMESTAMP_SIZE: u32 = 8;

/// Bytes of message body guaranteed present for a fixed-size message: `_rpc_id`.
const FIXED_HEADER_SIZE: u32 = 2;

/// Bytes of message body guaranteed present for a dynamic-size message:
/// `_rpc_id` followed by `_len`. `render_parser` rejects `_len < 4`.
const DYNAMIC_HEADER_SIZE: u32 = 4;

/// Descriptor for one contiguous element-queue storage region.
///
/// Field-for-field identical to the `EqView` struct crossing the cxx bridge
/// (`crates/reducer/src/ffi.rs`), so a bridge value converts by copy. The
/// pointer refers to memory owned by the C++ side, laid out as
/// `[shared header][element ring][data buffer]` — see [`contig_size`].
#[derive(Debug, Clone, Copy)]
pub struct EqView {
    /// Base pointer to the contiguous storage region (shared with C++).
    pub data: *mut u8,
    /// Element ring size in elements; must be a power of two.
    pub n_elems: u32,
    /// Data buffer size in bytes; must be a power of two.
    pub buf_len: u32,
}

impl EqView {
    /// Expected byte size of the storage region this descriptor points at.
    pub fn storage_size(&self) -> usize {
        contig_size(self.n_elems, self.buf_len)
    }
}

/// Whether a message carries a `_len` field, i.e. whether its encoded length
/// varies with its dynamic payloads.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum MessageKind {
    /// Fixed-size message: length comes from the registered metadata.
    Fixed,
    /// Dynamic-size message: length is carried in the `_len` header field.
    Dynamic,
}

/// The exact encoded length of one message, as the generated encoders compute
/// it: `timestamp + packed wire struct + dynamic payloads`.
///
/// Constructing this type is the only place message sizing happens, and it
/// rejects the sizes an encoder would otherwise panic on (`_len` overflowing
/// `u16`) or the parser would reject (`_len < 4`).
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct MessageSize {
    total: u32,
    kind: MessageKind,
}

impl MessageSize {
    /// Size of a fixed-size message whose packed wire struct is `wire_size`
    /// bytes (the generated `..._WIRE_SIZE` constant).
    ///
    /// # Errors
    ///
    /// [`EqError::InvalidArg`] if `wire_size` cannot hold an `_rpc_id`.
    pub fn fixed(wire_size: u32) -> Result<Self, EqError> {
        if wire_size < FIXED_HEADER_SIZE {
            return Err(EqError::InvalidArg);
        }
        Ok(Self {
            total: TIMESTAMP_SIZE + wire_size,
            kind: MessageKind::Fixed,
        })
    }

    /// Size of a dynamic-size message: its packed wire struct plus the byte
    /// lengths of its dynamic payloads, in encode order.
    ///
    /// # Errors
    ///
    /// [`EqError::InvalidArg`] if `wire_size` cannot hold `_rpc_id` and `_len`,
    /// or if the body length would overflow the `u16` `_len` field — the case
    /// the generated encoders assert on.
    pub fn dynamic<I>(wire_size: u32, payload_lens: I) -> Result<Self, EqError>
    where
        I: IntoIterator<Item = usize>,
    {
        if wire_size < DYNAMIC_HEADER_SIZE {
            return Err(EqError::InvalidArg);
        }
        let body = payload_lens
            .into_iter()
            .try_fold(u64::from(wire_size), |acc, len| {
                acc.checked_add(len as u64).ok_or(EqError::InvalidArg)
            })?;
        if body > u64::from(u16::MAX) {
            return Err(EqError::InvalidArg);
        }
        Ok(Self {
            total: TIMESTAMP_SIZE + body as u32,
            kind: MessageKind::Dynamic,
        })
    }

    /// Total element length in bytes, including the timestamp. This is the
    /// value to pass as the encoder's `__dest_len`.
    #[inline]
    pub fn total(self) -> u32 {
        self.total
    }

    /// Message body length in bytes, excluding the timestamp. For dynamic
    /// messages this equals the encoded `_len` field.
    #[inline]
    pub fn body_len(self) -> u32 {
        self.total - TIMESTAMP_SIZE
    }

    /// Whether the message carries a `_len` field.
    #[inline]
    pub fn kind(self) -> MessageKind {
        self.kind
    }
}

/// Producer handle over one element queue's storage.
///
/// Not `Send`/`Sync`: it holds raw pointers into memory shared with C++, and
/// the batching protocol assumes a single producer per queue.
#[derive(Debug)]
pub struct EqWriter {
    queue: ElementQueue,
}

impl EqWriter {
    /// Build a writer over an existing queue handle.
    pub fn from_queue(queue: ElementQueue) -> Self {
        Self { queue }
    }

    /// Build a writer over a contiguous storage region described by `view`.
    ///
    /// # Safety
    ///
    /// `view.data` must point to at least [`EqView::storage_size`] writable
    /// bytes with the element-queue layout, stay valid for the writer's
    /// lifetime, and have no other producer attached to it.
    pub unsafe fn from_view(view: EqView) -> Result<Self, EqError> {
        // SAFETY: delegated to the caller's contract above.
        let queue =
            unsafe { ElementQueue::new_from_contiguous(view.n_elems, view.buf_len, view.data)? };
        Ok(Self::from_queue(queue))
    }

    /// Build one writer per descriptor, preserving order, as the read side does
    /// in `QueueHandler::new_from_views`.
    ///
    /// # Safety
    ///
    /// Every element of `views` must satisfy [`EqWriter::from_view`]'s contract.
    pub unsafe fn from_views(views: &[EqView]) -> Result<Vec<Self>, EqError> {
        views
            .iter()
            // SAFETY: delegated to the caller's contract above.
            .map(|view| unsafe { Self::from_view(*view) })
            .collect()
    }

    /// Start a batch of writes. Nothing becomes visible to the consumer until
    /// [`MessageBatch::commit`]; dropping the batch discards it.
    pub fn batch(&mut self) -> MessageBatch<'_> {
        MessageBatch {
            batch: self.queue.start_write(),
        }
    }

    /// Encode one message and publish it immediately.
    ///
    /// Convenience over [`EqWriter::batch`] for callers emitting a single
    /// message; prefer a batch when emitting several, to publish once.
    pub fn write_message<F>(&mut self, size: MessageSize, encode: F) -> Result<(), EqError>
    where
        F: FnOnce(*mut u8, u32),
    {
        let mut batch = self.batch();
        batch.encode(size, encode)?;
        batch.commit();
        Ok(())
    }

    /// The underlying queue, for capacity and occupancy inspection.
    pub fn queue(&self) -> &ElementQueue {
        &self.queue
    }
}

/// A batch of message writes, published atomically on [`MessageBatch::commit`].
pub struct MessageBatch<'w> {
    batch: WriteBatch<'w>,
}

impl MessageBatch<'_> {
    /// Reserve `size.total()` bytes in the ring buffer and let `encode` fill
    /// them.
    ///
    /// `encode` receives the destination pointer and its length, matching the
    /// generated encoder signature (`__dest`, `__dest_len`). The pointer is
    /// valid for exactly `size.total()` bytes for the duration of the call.
    ///
    /// # Errors
    ///
    /// - [`EqError::NoSpace`] if the element ring or the data buffer is full.
    ///   The batch stays usable; the message was not written.
    /// - [`EqError::InvalidArg`] if the message cannot fit in the queue's data
    ///   buffer at any occupancy.
    ///
    /// # Panics
    ///
    /// The generated encoders assert that their `__dest_len` equals the length
    /// they compute, so a `size` that disagrees with the arguments passed to
    /// the encoder panics inside `encode`. In debug builds this method also
    /// cross-checks the `_len` field a dynamic message encoded against
    /// `size.body_len()`, which catches the same class of mistake for messages
    /// whose encoder is more permissive.
    pub fn encode<F>(&mut self, size: MessageSize, encode: F) -> Result<(), EqError>
    where
        F: FnOnce(*mut u8, u32),
    {
        let total = size.total();
        let dest = self.batch.write(total)?;
        debug_assert_eq!(dest.len(), total as usize);

        encode(dest.as_mut_ptr(), total);

        #[cfg(debug_assertions)]
        if let Some(declared) = encoded_body_len(dest, size.kind()) {
            debug_assert_eq!(
                declared,
                size.body_len(),
                "encoder wrote a _len disagreeing with the reserved element size"
            );
        }
        Ok(())
    }

    /// Publish every message written in this batch to the consumer.
    pub fn commit(self) {
        let _ = self.batch.finish();
    }

    /// Discard every message written in this batch.
    ///
    /// Explicit form of the drop behaviour, for call sites that abandon a batch
    /// on an error path and want to say so.
    pub fn discard(self) {
        // Returning without `finish()` leaves the published tails untouched, so
        // the consumer never sees the reserved elements.
    }
}

/// The body length a just-encoded element declares, when it declares one.
///
/// `None` for fixed-size messages (no `_len` field) and for bodies too short to
/// hold one, so a debug assertion can compare against an expected value
/// without duplicating the layout rules.
#[cfg(debug_assertions)]
fn encoded_body_len(element: &[u8], kind: MessageKind) -> Option<u32> {
    match kind {
        MessageKind::Fixed => None,
        MessageKind::Dynamic => {
            let ts = TIMESTAMP_SIZE as usize;
            let len_at = ts + 2;
            let bytes = element.get(len_at..len_at + 2)?;
            Some(u32::from(u16::from_ne_bytes([bytes[0], bytes[1]])))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemElementQueueStorage;

    #[test]
    fn fixed_size_adds_timestamp() {
        let size = MessageSize::fixed(48).unwrap();
        assert_eq!(size.total(), 56);
        assert_eq!(size.body_len(), 48);
        assert_eq!(size.kind(), MessageKind::Fixed);
    }

    #[test]
    fn dynamic_size_sums_payloads() {
        let size = MessageSize::dynamic(21, [3usize, 5, 0]).unwrap();
        assert_eq!(size.body_len(), 29);
        assert_eq!(size.total(), 37);
        assert_eq!(size.kind(), MessageKind::Dynamic);
    }

    #[test]
    fn wire_size_must_hold_the_headers() {
        assert_eq!(MessageSize::fixed(1), Err(EqError::InvalidArg));
        assert_eq!(MessageSize::dynamic(3, []), Err(EqError::InvalidArg));
    }

    #[test]
    fn dynamic_body_overflowing_u16_is_rejected() {
        let err = MessageSize::dynamic(21, [u16::MAX as usize]).unwrap_err();
        assert_eq!(err, EqError::InvalidArg);
    }

    #[test]
    fn commit_publishes_and_drop_discards() {
        let storage = MemElementQueueStorage::new(8, 256);
        let mut writer = storage.make_writer().unwrap();
        // Separate consumer handle over the same storage, as C++ readers attach.
        let mut reader = storage.make_queue().unwrap();

        let size = MessageSize::fixed(8).unwrap();
        writer
            .write_message(size, |dest, len| fill(dest, len, 0xAA))
            .unwrap();

        {
            let mut batch = writer.batch();
            batch
                .encode(size, |dest, len| fill(dest, len, 0xBB))
                .unwrap();
            batch.discard();
        }

        let rb = reader.start_read();
        assert_eq!(rb.read().unwrap()[8], 0xAA);
        assert_eq!(rb.read(), Err(EqError::NoEntry));
        let _ = rb.finish();
    }

    #[test]
    fn message_larger_than_the_data_buffer_is_rejected() {
        let storage = MemElementQueueStorage::new(8, 64);
        let mut writer = storage.make_writer().unwrap();
        let size = MessageSize::fixed(120).unwrap();
        let err = writer
            .write_message(size, |dest, len| fill(dest, len, 0))
            .unwrap_err();
        assert_eq!(err, EqError::InvalidArg);
    }

    /// Stand-in for a generated encoder: writes a timestamp then a filler byte
    /// pattern over the message body.
    fn fill(dest: *mut u8, dest_len: u32, byte: u8) {
        assert!(!dest.is_null());
        // SAFETY: `encode` guarantees `dest` is valid for `dest_len` bytes.
        let dst = unsafe { core::slice::from_raw_parts_mut(dest, dest_len as usize) };
        dst[..8].copy_from_slice(&1_u64.to_ne_bytes());
        dst[8..].fill(byte);
    }
}
