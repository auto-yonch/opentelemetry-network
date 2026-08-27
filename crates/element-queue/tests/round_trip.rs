//! Round-trip tests across the two generated codec halves.
//!
//! Write side: [`EqWriter`] reserves an element and a render-generated
//! `ebpf_net_matching_encode_*` function fills it. Read side: the same
//! ring-buffer read path the C++ readers use ([`ElementQueue::start_read`]),
//! then `render_parser::Parser` keyed on the render-generated perfect hash
//! (`matching_hash`), then the generated `parsed_message` decoder.
//!
//! Anything the writer gets wrong about element sizing, timestamp placement,
//! or ring-buffer mechanics shows up here as a decode error or a field
//! mismatch, which is what makes this the gate for the write side.

use core::ffi::c_char;

use element_queue::{EqWriter, MemElementQueueStorage, MessageSize};
use encoder_ebpf_net_matching::encoder;
use encoder_ebpf_net_matching::hash::{matching_hash, MATCHING_HASH_SIZE};
use encoder_ebpf_net_matching::parsed_message;
use encoder_ebpf_net_matching::wire_messages::{
    jb_matching__agent_info, jb_matching__flow_start, AGENT_INFO_WIRE_SIZE, FLOW_START_WIRE_SIZE,
};
use encoder_ebpf_net_matching::JbBlob;
use render_parser::Parser;

/// A `flow_start` message: fixed-size, no dynamic payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FlowStart {
    timestamp: u64,
    flow_ref: u64,
    addr1: u128,
    port1: u16,
    addr2: u128,
    port2: u16,
}

impl FlowStart {
    fn write(&self, writer: &mut EqWriter) {
        let size = MessageSize::fixed(FLOW_START_WIRE_SIZE as u32).expect("flow_start size");
        writer
            .write_message(size, |dest, dest_len| {
                encoder::ebpf_net_matching_encode_flow_start(
                    dest,
                    dest_len,
                    self.timestamp,
                    self.flow_ref,
                    self.addr1,
                    self.port1,
                    self.addr2,
                    self.port2,
                )
            })
            .expect("flow_start write");
    }
}

/// An `agent_info` message: dynamic-size, five string payloads. `ns` is the
/// trailing payload whose length the decoder derives from `_len`, so a writer
/// that mis-sizes the element corrupts exactly that field.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AgentInfo {
    timestamp: u64,
    agent_ref: u64,
    side: u8,
    id: String,
    az: String,
    env: String,
    role: String,
    ns: String,
}

impl AgentInfo {
    fn size(&self) -> MessageSize {
        MessageSize::dynamic(
            AGENT_INFO_WIRE_SIZE as u32,
            [
                self.id.len(),
                self.az.len(),
                self.env.len(),
                self.role.len(),
                self.ns.len(),
            ],
        )
        .expect("agent_info size")
    }

    fn write(&self, writer: &mut EqWriter) {
        let size = self.size();
        writer
            .write_message(size, |dest, dest_len| {
                encoder::ebpf_net_matching_encode_agent_info(
                    dest,
                    dest_len,
                    self.timestamp,
                    self.agent_ref,
                    self.side,
                    blob(&self.id),
                    blob(&self.az),
                    blob(&self.env),
                    blob(&self.role),
                    blob(&self.ns),
                )
            })
            .expect("agent_info write");
    }
}

/// Borrow a `&str` as the generated encoders' blob argument.
fn blob(s: &str) -> JbBlob {
    JbBlob {
        buf: s.as_ptr() as *const c_char,
        len: u16::try_from(s.len()).expect("payload fits in u16"),
    }
}

/// Which message a registered rpc_id refers to, so the read side can dispatch
/// the way a real core would instead of assuming an order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MessageTag {
    FlowStart,
    AgentInfo,
}

/// Parser registered for exactly the two messages under test, keyed on the
/// render-generated perfect hash.
fn matching_parser() -> Parser<MessageTag, fn(u32) -> u32> {
    let mut parser: Parser<MessageTag, fn(u32) -> u32> =
        Parser::new(MATCHING_HASH_SIZE as usize, matching_hash);
    parser
        .add_message(jb_matching__flow_start::metadata(), MessageTag::FlowStart)
        .expect("register flow_start");
    parser
        .add_message(jb_matching__agent_info::metadata(), MessageTag::AgentInfo)
        .expect("register agent_info");
    parser
}

/// What the read side recovered from one element.
#[derive(Debug, PartialEq, Eq)]
enum Decoded {
    FlowStart(FlowStart),
    AgentInfo(AgentInfo),
}

/// Drain every published element through the C++-equivalent read path and
/// decode it with the generated decoders.
fn drain(
    storage: &MemElementQueueStorage,
    parser: &Parser<MessageTag, fn(u32) -> u32>,
) -> Vec<Decoded> {
    let mut reader = storage.make_queue().expect("reader queue");
    let mut out = Vec::new();
    let rb = reader.start_read();
    while let Ok(bytes) = rb.read() {
        let ok = parser.handle(bytes).expect("parse element");
        out.push(match ok.value {
            MessageTag::FlowStart => {
                let m = parsed_message::flow_start::decode(ok.message).expect("decode flow_start");
                Decoded::FlowStart(FlowStart {
                    timestamp: ok.timestamp,
                    flow_ref: m._ref,
                    addr1: m.addr1,
                    port1: m.port1,
                    addr2: m.addr2,
                    port2: m.port2,
                })
            }
            MessageTag::AgentInfo => {
                let m = parsed_message::agent_info::decode(ok.message).expect("decode agent_info");
                Decoded::AgentInfo(AgentInfo {
                    timestamp: ok.timestamp,
                    agent_ref: m._ref,
                    side: m.side,
                    id: m.id,
                    az: m.az,
                    env: m.env,
                    role: m.role,
                    ns: m.ns,
                })
            }
        });
    }
    let _ = rb.finish();
    out
}

fn sample_flow_start(seq: u64) -> FlowStart {
    FlowStart {
        timestamp: 1_700_000_000_000_000_000 + seq,
        flow_ref: 0xDEAD_BEEF_0000_0000 | seq,
        addr1: 0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10,
        port1: 443,
        addr2: u128::from(u32::MAX) | (1 << 100),
        port2: 51_000 + seq as u16,
    }
}

fn sample_agent_info(seq: u64) -> AgentInfo {
    AgentInfo {
        timestamp: 1_700_000_000_000_000_777 + seq,
        agent_ref: 0x0BAD_F00D_0000_0000 | seq,
        side: (seq % 2) as u8,
        id: format!("agent-{seq}"),
        az: "us-east-1a".to_string(),
        env: "production".to_string(),
        role: "reducer".to_string(),
        ns: format!("namespace-with-a-longer-value-{seq}"),
    }
}

/// A fixed-size message survives encoder → ring buffer → parser → decoder with
/// every field and the timestamp intact.
#[test]
fn fixed_size_message_round_trips() {
    let storage = MemElementQueueStorage::new(16, 4096);
    let mut writer = storage.make_writer().expect("writer");
    let parser = matching_parser();

    let expected = sample_flow_start(1);
    expected.write(&mut writer);

    assert_eq!(drain(&storage, &parser), vec![Decoded::FlowStart(expected)]);
}

/// A dynamic-payload message round-trips, including the trailing payload whose
/// length the decoder derives from `_len` rather than from a header field.
#[test]
fn dynamic_payload_message_round_trips() {
    let storage = MemElementQueueStorage::new(16, 4096);
    let mut writer = storage.make_writer().expect("writer");
    let parser = matching_parser();

    let expected = sample_agent_info(7);
    expected.write(&mut writer);

    assert_eq!(drain(&storage, &parser), vec![Decoded::AgentInfo(expected)]);
}

/// Empty dynamic payloads are a distinct case: the encoder skips them entirely,
/// so `_len` is the only thing telling the decoder where the body ends.
#[test]
fn dynamic_message_with_empty_payloads_round_trips() {
    let storage = MemElementQueueStorage::new(16, 4096);
    let mut writer = storage.make_writer().expect("writer");
    let parser = matching_parser();

    let expected = AgentInfo {
        timestamp: 42,
        agent_ref: 9,
        side: 1,
        id: String::new(),
        az: String::new(),
        env: String::new(),
        role: String::new(),
        ns: String::new(),
    };
    expected.write(&mut writer);

    assert_eq!(drain(&storage, &parser), vec![Decoded::AgentInfo(expected)]);
}

/// One batch carrying both message shapes publishes atomically and preserves
/// write order across the mixed element sizes.
#[test]
fn mixed_batch_preserves_order() {
    let storage = MemElementQueueStorage::new(16, 4096);
    let mut writer = storage.make_writer().expect("writer");
    let parser = matching_parser();

    let flow = sample_flow_start(3);
    let agent = sample_agent_info(3);

    // Nothing is visible to the consumer before the batch commits.
    let mut batch = writer.batch();
    let flow_size = MessageSize::fixed(FLOW_START_WIRE_SIZE as u32).unwrap();
    batch
        .encode(flow_size, |dest, len| {
            encoder::ebpf_net_matching_encode_flow_start(
                dest,
                len,
                flow.timestamp,
                flow.flow_ref,
                flow.addr1,
                flow.port1,
                flow.addr2,
                flow.port2,
            )
        })
        .unwrap();
    batch
        .encode(agent.size(), |dest, len| {
            encoder::ebpf_net_matching_encode_agent_info(
                dest,
                len,
                agent.timestamp,
                agent.agent_ref,
                agent.side,
                blob(&agent.id),
                blob(&agent.az),
                blob(&agent.env),
                blob(&agent.role),
                blob(&agent.ns),
            )
        })
        .unwrap();
    assert!(drain(&storage, &parser).is_empty());

    batch.commit();

    assert_eq!(
        drain(&storage, &parser),
        vec![Decoded::FlowStart(flow), Decoded::AgentInfo(agent.clone()),]
    );
}

/// Sustained write/read cycles wrap both the element ring and the data buffer
/// many times over. Elements are never split across the wrap point, so every
/// message must still decode after the offsets fold back to zero.
#[test]
fn round_trips_across_ring_and_buffer_wrap() {
    // Small rings: 8 elements and 512 bytes force repeated wrapping while the
    // largest message here is ~100 bytes.
    let storage = MemElementQueueStorage::new(8, 512);
    let mut writer = storage.make_writer().expect("writer");
    let parser = matching_parser();

    for seq in 0..200u64 {
        let flow = sample_flow_start(seq);
        let agent = sample_agent_info(seq);

        flow.write(&mut writer);
        agent.write(&mut writer);

        assert_eq!(
            drain(&storage, &parser),
            vec![Decoded::FlowStart(flow), Decoded::AgentInfo(agent)],
            "round trip failed at seq={seq}"
        );
    }
}

/// A full data buffer is reported, not silently truncated, and the queue stays
/// usable once the consumer drains it.
#[test]
fn full_queue_reports_no_space_and_recovers() {
    let storage = MemElementQueueStorage::new(8, 512);
    let mut writer = storage.make_writer().expect("writer");
    let parser = matching_parser();

    let size = MessageSize::fixed(FLOW_START_WIRE_SIZE as u32).unwrap();
    let flow = sample_flow_start(11);
    let encode = |dest: *mut u8, len: u32| {
        encoder::ebpf_net_matching_encode_flow_start(
            dest,
            len,
            flow.timestamp,
            flow.flow_ref,
            flow.addr1,
            flow.port1,
            flow.addr2,
            flow.port2,
        )
    };

    let mut batch = writer.batch();
    let mut written = 0usize;
    while batch.encode(size, encode).is_ok() {
        written += 1;
        assert!(written <= 64, "queue never reported NoSpace");
    }
    assert!(written > 0, "queue rejected the first message");
    batch.commit();

    let drained = drain(&storage, &parser);
    assert_eq!(drained.len(), written);
    assert!(drained.iter().all(|d| *d == Decoded::FlowStart(flow)));

    // With the consumer's heads published, the writer has room again.
    flow.write(&mut writer);
    assert_eq!(drain(&storage, &parser), vec![Decoded::FlowStart(flow)]);
}
