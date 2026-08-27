//! IPv6 addresses as the matching core handles them (`util/ip_address.h`).
//!
//! Every address on the wire is 16 bytes, but most are IPv4-mapped
//! (`::ffff:a.b.c.d`). `tidy_string` is the C++ spelling used for the `id` and
//! `address` node fields, so the strings this core sends to aggregation must
//! match it: IPv4-mapped addresses print as dotted quads, everything else as a
//! compressed IPv6 literal.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

/// A 128-bit address in network byte order, as it arrives on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct IPv6Address([u8; 16]);

/// `169.254.169.254`: the cloud instance-metadata endpoint, which resolves to a
/// synthetic node rather than a peer.
pub const ADDR_INSTANCE_METADATA: IPv6Address = IPv6Address::from_ipv4_octets([169, 254, 169, 254]);

impl IPv6Address {
    /// Wraps the 16 wire bytes.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The IPv4-mapped form of an IPv4 address (`::ffff:a.b.c.d`).
    pub const fn from_ipv4_octets(octets: [u8; 4]) -> Self {
        Self([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, octets[0], octets[1], octets[2], octets[3],
        ])
    }

    /// The wire bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// The address as the `u128` the AWS enrichment key uses
    /// (`aws_enrichment.by_key({ipv6.as_int()})`).
    ///
    /// Native-endian on purpose: the C++ `as_int` reinterprets the same 16
    /// stored bytes, and the `aws_enrichment_start.ip` field the generated
    /// decoder hands us is `u128::from_ne_bytes` over those bytes. Reading it
    /// as big-endian here would key every enrichment span under a byte-swapped
    /// address and quietly resolve nothing.
    pub fn as_int(&self) -> u128 {
        u128::from_ne_bytes(self.0)
    }

    /// Builds from the `u128` the `aws_enrichment_start` message carries.
    pub fn from_int(value: u128) -> Self {
        Self(value.to_ne_bytes())
    }

    /// The embedded IPv4 address, when this is an IPv4-mapped address.
    pub fn to_ipv4(self) -> Option<Ipv4Addr> {
        let addr = Ipv6Addr::from(self.0);
        addr.to_ipv4_mapped()
    }

    /// `IPv6Address::tidy_string`: dotted quad for IPv4-mapped addresses, a
    /// compressed IPv6 literal otherwise.
    pub fn tidy_string(&self) -> String {
        match self.to_ipv4() {
            Some(v4) => v4.to_string(),
            None => Ipv6Addr::from(self.0).to_string(),
        }
    }
}

impl fmt::Display for IPv6Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.tidy_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_mapped_prints_as_a_dotted_quad() {
        let addr = IPv6Address::from_ipv4_octets([10, 0, 0, 7]);
        assert_eq!(addr.tidy_string(), "10.0.0.7");
        assert_eq!(addr.to_ipv4(), Some(Ipv4Addr::new(10, 0, 0, 7)));
    }

    #[test]
    fn native_ipv6_prints_compressed() {
        let mut bytes = [0u8; 16];
        bytes[0] = 0x20;
        bytes[1] = 0x01;
        bytes[15] = 0x01;
        assert_eq!(IPv6Address::from_bytes(bytes).tidy_string(), "2001::1");
    }

    #[test]
    fn instance_metadata_address_is_the_link_local_endpoint() {
        assert_eq!(ADDR_INSTANCE_METADATA.tidy_string(), "169.254.169.254");
    }

    /// The AWS enrichment key is the host-order integer, so the conversion has
    /// to round-trip exactly — a byte-order slip would look up the wrong span.
    #[test]
    fn integer_form_round_trips() {
        let addr = IPv6Address::from_ipv4_octets([192, 168, 1, 1]);
        assert_eq!(IPv6Address::from_int(addr.as_int()), addr);
    }
}
