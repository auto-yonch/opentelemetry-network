//! Typed builders over the render-generated encoders.
//!
//! The generated functions (`crates/render/ebpf_net/*/src/encoder.rs`) are flat
//! C-style: a destination pointer, an exact destination length, a timestamp,
//! then one argument per field. They assert that the buffer length matches the
//! encoded length exactly, so every caller has to recompute
//! `8 + fixed_wire_size + Σ blob lengths` by hand -- which is where a test
//! silently turns into a panic in generated code.
//!
//! The builders here own that arithmetic: each returns an [`Encoded`] element
//! ready to hand to `Core::inject`, with jitbuf-`Writer`-style ergonomics
//! (`matching::pulse(t)`, `matching::agent_info(t, ref, side, id, az, ...)`).
//!
//! Adding a message is two lines: take the `*_WIRE_SIZE` constant from the
//! app's `wire_messages` module, and pass the blob lengths that follow it. See
//! [`matching::agent_info`] for the blob-carrying shape.

/// Bytes of native-endian timestamp that prefix every queue element.
pub const TIMESTAMP_LEN: usize = 8;

/// One encoded queue element: an 8-byte native-endian timestamp followed by the
/// wire message, which is exactly what the reducer's element queues carry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Encoded {
    bytes: Vec<u8>,
}

impl Encoded {
    /// The whole element, timestamp included -- what `Core::inject` takes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The message without its timestamp prefix -- what the generated
    /// `parsed_message::*::decode` functions take.
    pub fn body(&self) -> &[u8] {
        &self.bytes[TIMESTAMP_LEN..]
    }

    /// The timestamp this element was encoded with.
    pub fn timestamp(&self) -> u64 {
        let mut ts = [0u8; TIMESTAMP_LEN];
        ts.copy_from_slice(&self.bytes[..TIMESTAMP_LEN]);
        u64::from_ne_bytes(ts)
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl AsRef<[u8]> for Encoded {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Allocates the exact-length buffer a generated encoder demands and runs it.
///
/// `fixed_wire_size` is the message's `*_WIRE_SIZE` constant; `blob_bytes` is
/// the total length of the blob payloads that trail the fixed part.
///
/// Panics if the encoded length would not fit the `u16` length field the wire
/// format uses -- the same limit the generated code asserts on, but reported
/// against the builder's inputs rather than from inside generated code.
pub fn encode_exact(
    fixed_wire_size: usize,
    blob_bytes: usize,
    encode: impl FnOnce(*mut u8, u32),
) -> Encoded {
    let consumed = fixed_wire_size + blob_bytes;
    assert!(
        consumed <= u16::MAX as usize,
        "encoded message of {consumed} bytes exceeds the {} byte wire limit",
        u16::MAX
    );

    let mut bytes = vec![0u8; TIMESTAMP_LEN + consumed];
    let len = bytes.len() as u32;
    encode(bytes.as_mut_ptr(), len);

    Encoded { bytes }
}

/// Length of a blob field, checked against the `u16` the wire format carries.
fn blob_len(field: &'static str, value: &str) -> u16 {
    u16::try_from(value.len())
        .unwrap_or_else(|_| panic!("blob field `{field}` is longer than {} bytes", u16::MAX))
}

/// Messages the matching core receives from ingest, plus its pulse.
pub mod matching {
    use super::{blob_len, encode_exact, Encoded};
    use core::ffi::c_char;
    use encoder_ebpf_net_matching::encoder;
    use encoder_ebpf_net_matching::wire_messages as wire;
    use encoder_ebpf_net_matching::JbBlob;

    fn blob(field: &'static str, value: &str) -> JbBlob {
        JbBlob {
            buf: value.as_ptr() as *const c_char,
            len: blob_len(field, value),
        }
    }

    /// The clock-advancing message: carries a timestamp and nothing else.
    pub fn pulse(timestamp: u64) -> Encoded {
        encode_exact(wire::PULSE_WIRE_SIZE, 0, |dest, len| {
            encoder::ebpf_net_matching_encode_pulse(dest, len, timestamp)
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn flow_start(
        timestamp: u64,
        flow_ref: u64,
        addr1: u128,
        port1: u16,
        addr2: u128,
        port2: u16,
    ) -> Encoded {
        encode_exact(wire::FLOW_START_WIRE_SIZE, 0, |dest, len| {
            encoder::ebpf_net_matching_encode_flow_start(
                dest, len, timestamp, flow_ref, addr1, port1, addr2, port2,
            )
        })
    }

    pub fn flow_end(timestamp: u64, flow_ref: u64) -> Encoded {
        encode_exact(wire::FLOW_END_WIRE_SIZE, 0, |dest, len| {
            encoder::ebpf_net_matching_encode_flow_end(dest, len, timestamp, flow_ref)
        })
    }

    /// Blob-carrying message: the builder sizes the buffer from the fixed part
    /// plus the five string payloads.
    #[allow(clippy::too_many_arguments)]
    pub fn agent_info(
        timestamp: u64,
        agent_ref: u64,
        side: u8,
        id: &str,
        az: &str,
        env: &str,
        role: &str,
        ns: &str,
    ) -> Encoded {
        let blobs = id.len() + az.len() + env.len() + role.len() + ns.len();

        encode_exact(wire::AGENT_INFO_WIRE_SIZE, blobs, |dest, len| {
            encoder::ebpf_net_matching_encode_agent_info(
                dest,
                len,
                timestamp,
                agent_ref,
                side,
                blob("id", id),
                blob("az", az),
                blob("env", env),
                blob("role", role),
                blob("ns", ns),
            )
        })
    }
}

/// Messages the logging core receives.
pub mod logging {
    use super::{encode_exact, Encoded};
    use encoder_ebpf_net_logging::encoder;
    use encoder_ebpf_net_logging::wire_messages as wire;

    pub fn pulse(timestamp: u64) -> Encoded {
        encode_exact(wire::PULSE_WIRE_SIZE, 0, |dest, len| {
            encoder::ebpf_net_logging_encode_pulse(dest, len, timestamp)
        })
    }

    pub fn logger_start(timestamp: u64, logger_ref: u64) -> Encoded {
        encode_exact(wire::LOGGER_START_WIRE_SIZE, 0, |dest, len| {
            encoder::ebpf_net_logging_encode_logger_start(dest, len, timestamp, logger_ref)
        })
    }

    pub fn logger_end(timestamp: u64, logger_ref: u64) -> Encoded {
        encode_exact(wire::LOGGER_END_WIRE_SIZE, 0, |dest, len| {
            encoder::ebpf_net_logging_encode_logger_end(dest, len, timestamp, logger_ref)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: u64 = 1_500_000_000_000_000_000;

    #[test]
    fn encoded_element_carries_timestamp_then_body() {
        let msg = matching::pulse(T0);

        assert_eq!(msg.len(), TIMESTAMP_LEN + 2);
        assert_eq!(msg.timestamp(), T0);
        // The pulse body is just its rpc id.
        assert_eq!(msg.body(), &65535u16.to_ne_bytes());
    }

    #[test]
    fn fixed_message_length_comes_from_the_wire_size() {
        let msg = matching::flow_start(T0, 7, 1, 80, 2, 443);

        assert_eq!(
            msg.len(),
            TIMESTAMP_LEN + encoder_ebpf_net_matching::wire_messages::FLOW_START_WIRE_SIZE
        );
        assert_eq!(msg.timestamp(), T0);
    }

    #[test]
    fn blob_message_length_includes_every_payload() {
        let msg = matching::agent_info(T0, 7, 0, "id", "az", "env", "role", "ns");

        let blobs = "id".len() + "az".len() + "env".len() + "role".len() + "ns".len();
        assert_eq!(
            msg.len(),
            TIMESTAMP_LEN + encoder_ebpf_net_matching::wire_messages::AGENT_INFO_WIRE_SIZE + blobs
        );
    }

    #[test]
    fn empty_blobs_are_encodable() {
        let msg = matching::agent_info(T0, 7, 0, "", "", "", "", "");

        assert_eq!(
            msg.len(),
            TIMESTAMP_LEN + encoder_ebpf_net_matching::wire_messages::AGENT_INFO_WIRE_SIZE
        );
    }

    #[test]
    fn logging_builders_encode_their_own_app() {
        let msg = logging::logger_start(T0, 3);

        assert_eq!(
            msg.len(),
            TIMESTAMP_LEN + encoder_ebpf_net_logging::wire_messages::LOGGER_START_WIRE_SIZE
        );
        assert_eq!(msg.timestamp(), T0);
    }
}
