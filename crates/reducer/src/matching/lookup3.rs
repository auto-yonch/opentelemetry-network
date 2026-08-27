//! Port of Bob Jenkins' lookup3 hash as the reducer uses it (`util/lookup3.c`).
//!
//! Two call sites in the matching core need bit-exact agreement with the C++
//! implementation, because both hash values are compared against values the
//! C++ side computed:
//!
//! * `uid_to_u64` (`reducer/uid_key.cc`) builds the `(uid_suffix, uid_hash)`
//!   key that the ingest core stamps on `k8s_info` / `set_container_pod`
//!   messages; the matching core recomputes it from a cgroup-derived container
//!   id and looks the container up by that key.
//! * the render-generated `hash_sharding_key` picks which aggregation shard an
//!   `agg_root` proxy writes to. A different hash would send a flow's metrics
//!   to a different aggregation shard than the C++ core does, silently
//!   splitting one logical aggregation root across shards.
//!
//! `util/lookup3.c` has three read paths (u32-aligned, u16-aligned, byte-wise)
//! that all produce the same result on a little-endian machine — the property
//! its own self-test asserts. Only the byte-wise path is ported here: it has no
//! alignment precondition, and `lookup3_parity` (tests) checks it against the
//! C implementation over a spread of lengths and seeds.

/// `mix(a, b, c)` from `util/lookup3.c`.
#[inline]
fn mix(mut a: u32, mut b: u32, mut c: u32) -> (u32, u32, u32) {
    a = a.wrapping_sub(c);
    a ^= c.rotate_left(4);
    c = c.wrapping_add(b);
    b = b.wrapping_sub(a);
    b ^= a.rotate_left(6);
    a = a.wrapping_add(c);
    c = c.wrapping_sub(b);
    c ^= b.rotate_left(8);
    b = b.wrapping_add(a);
    a = a.wrapping_sub(c);
    a ^= c.rotate_left(16);
    c = c.wrapping_add(b);
    b = b.wrapping_sub(a);
    b ^= a.rotate_left(19);
    a = a.wrapping_add(c);
    c = c.wrapping_sub(b);
    c ^= b.rotate_left(4);
    b = b.wrapping_add(a);
    (a, b, c)
}

/// `final(a, b, c)` from `util/lookup3.c`.
#[inline]
fn final_mix(mut a: u32, mut b: u32, mut c: u32) -> (u32, u32, u32) {
    c ^= b;
    c = c.wrapping_sub(b.rotate_left(14));
    a ^= c;
    a = a.wrapping_sub(c.rotate_left(11));
    b ^= a;
    b = b.wrapping_sub(a.rotate_left(25));
    c ^= b;
    c = c.wrapping_sub(b.rotate_left(16));
    a ^= c;
    a = a.wrapping_sub(c.rotate_left(4));
    b ^= a;
    b = b.wrapping_sub(a.rotate_left(14));
    c ^= b;
    c = c.wrapping_sub(b.rotate_left(24));
    (a, b, c)
}

/// `lookup3_hashlittle2`: two 32-bit hash values, `(pc, pb)` in and out.
///
/// A zero-length key returns the initial values unmixed, as the C does.
pub fn hashlittle2(key: &[u8], pc: u32, pb: u32) -> (u32, u32) {
    let seed = 0xdead_beef_u32
        .wrapping_add(key.len() as u32)
        .wrapping_add(pc);
    let (mut a, mut b, mut c) = (seed, seed, seed.wrapping_add(pb));

    let mut rest = key;
    while rest.len() > 12 {
        a = a.wrapping_add(word(&rest[0..4]));
        b = b.wrapping_add(word(&rest[4..8]));
        c = c.wrapping_add(word(&rest[8..12]));
        (a, b, c) = mix(a, b, c);
        rest = &rest[12..];
    }

    if rest.is_empty() {
        // Zero-length strings require no mixing.
        return (c, b);
    }

    // The C switch falls through from the tail length down to 1; adding the
    // present bytes at their own shifts is the same accumulation.
    for (i, byte) in rest.iter().enumerate() {
        let value = u32::from(*byte) << (8 * (i % 4));
        match i / 4 {
            0 => a = a.wrapping_add(value),
            1 => b = b.wrapping_add(value),
            _ => c = c.wrapping_add(value),
        }
    }

    let (_, b, c) = final_mix(a, b, c);
    (c, b)
}

/// `lookup3_hashlittle`: the primary 32-bit hash value.
///
/// Identical to [`hashlittle2`] with a zero secondary seed, which is what the
/// C implementation's own self-test asserts.
pub fn hashlittle(key: &[u8], initval: u32) -> u32 {
    hashlittle2(key, initval, 0).0
}

/// `reducer::uid_to_u64` (`reducer/uid_key.cc`): the 64-bit collision reducer
/// stamped alongside a pod or container UID suffix.
pub fn uid_to_u64(uid: &[u8]) -> u64 {
    let (pc, pb) = hashlittle2(uid, 0, 0);
    u64::from(pc) + (u64::from(pb) << 32)
}

/// Little-endian 32-bit word, as the C reads on a little-endian machine.
#[inline]
fn word(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vectors produced by linking `util/lookup3.c` and printing
    /// `lookup3_hashlittle2(input, len, &pc, &pb)` with `pc = initval`,
    /// `pb = 0`. They pin the port against the C implementation across the
    /// zero-length early return, every tail-length class, and a seeded call.
    const C_VECTORS: &[(&str, u32, u32, u32)] = &[
        // (input, initval, expected pc, expected pb)
        ("", 0, 0xdead_beef, 0xdead_beef),
        ("", 0xdead_beef, 0xbd5b_7dde, 0xbd5b_7dde),
        ("a", 0, 0x58d6_8708, 0x5826_47ac),
        ("abc", 0, 0x0e39_7631, 0x3c03_be9e),
        (
            "Four score and seven years ago",
            0,
            0x1777_0551,
            0xce72_26e6,
        ),
        (
            "Four score and seven years ago",
            1,
            0xcd62_8161,
            0x6cbe_a4b3,
        ),
        (
            "f55fb707-9bf6-4bf5-8a7e-19c5f3e52215",
            0,
            0x09be_6ad0,
            0x32c7_9e03,
        ),
        (
            "6f652f89943b50f7b101d13f11371daf34bf836b7e1b725b5e8b6439451018bd",
            0,
            0x05ae_f67d,
            0xa7a7_2a64,
        ),
    ];

    #[test]
    fn matches_c_implementation_vectors() {
        for (input, initval, expected_pc, expected_pb) in C_VECTORS {
            let (pc, pb) = hashlittle2(input.as_bytes(), *initval, 0);
            assert_eq!(
                (pc, pb),
                (*expected_pc, *expected_pb),
                "hashlittle2({input:?}, {initval:#x})"
            );
        }
    }

    #[test]
    fn hashlittle_is_hashlittle2_primary() {
        for (input, initval, expected_pc, _) in C_VECTORS {
            assert_eq!(hashlittle(input.as_bytes(), *initval), *expected_pc);
        }
    }

    /// Every tail length across a block boundary is exercised, so a mistake in
    /// the fall-through port shows up as a changed hash rather than silently
    /// mis-sharding one length class.
    #[test]
    fn every_tail_length_is_mixed() {
        let data = [0x5au8; 40];
        let mut seen = std::collections::HashSet::new();
        for len in 0..=data.len() {
            assert!(
                seen.insert(hashlittle(&data[..len], 0)),
                "length {len} collides with a shorter prefix"
            );
        }
    }

    /// Value taken from the same C harness, computed the way
    /// `reducer::uid_to_u64` composes the two words.
    #[test]
    fn uid_hash_matches_the_c_uid_key() {
        let uid = b"6f652f89943b50f7b101d13f11371daf34bf836b7e1b725b5e8b6439451018bd";
        assert_eq!(uid_to_u64(uid), 12_080_671_134_525_093_501);
    }
}
