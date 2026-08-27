//! Hand-rolled replacements for the render-generated matching-app spans:
//! bounded, key-indexed pools with per-queue reference tables.
//!
//! Per the spec's locked decision, the generated `Index` is not used by the
//! Rust core. What it provided is reproduced here explicitly:
//!
//! * **key indexing** — a span is found by its render `index (...)` tuple.
//! * **reference tables** — the ingest core addresses a span by a `_ref`
//!   handle it chose; the same handle from a *different* queue is a different
//!   span, so references are scoped by `(queue, reference)`.
//! * **reference counting** — two agents observing one flow both send
//!   `flow_start` for the same key; the span lives until the last `_end`.
//! * **bounded capacity** — the render `pool_size` becomes a hard limit, and
//!   exhaustion is reported instead of growing without bound.

use std::collections::hash_map::Entry as MapEntry;
use std::collections::HashMap;
use std::hash::Hash;

use super::ip::IPv6Address;
use super::lookup3;

/// `pool_size` of the matching `flow` span.
pub const FLOW_POOL_SIZE: usize = 4_200_000;
/// `pool_size` of the matching `aws_enrichment` span.
pub const AWS_ENRICHMENT_POOL_SIZE: usize = 60_000;
/// `pool_size` of the matching `k8s_pod` span.
pub const K8S_POD_POOL_SIZE: usize = 220_000;
/// `pool_size` of the matching `k8s_container` span.
pub const K8S_CONTAINER_POOL_SIZE: usize = 600_000;
/// `pool_size` of the matching `agg_root` span.
pub const AGG_ROOT_POOL_SIZE: usize = 4_800_000;

/// Length of the UID suffix carried in a `k8s_pod` / `k8s_container` key
/// (`reducer/uid_key.h`).
pub const UID_SUFFIX_LEN: usize = 64;

/// Why a `_start` could not be honoured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolError {
    /// The pool is at its render-declared `pool_size`.
    Exhausted,
}

/// An "UID key" (`reducer/uid_key.h`): the last 64 bytes of a Kubernetes UID
/// plus a hash of the whole UID, which together index the `k8s_pod` and
/// `k8s_container` spans.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PodKey {
    uid_suffix: [u8; UID_SUFFIX_LEN],
    uid_hash: u64,
}

impl PodKey {
    /// The key as it arrives on the wire.
    pub fn new(uid_suffix: [u8; UID_SUFFIX_LEN], uid_hash: u64) -> Self {
        Self {
            uid_suffix,
            uid_hash,
        }
    }

    /// `make_uid_key`: suffix of the UID (zero-padded when short) plus the
    /// lookup3 hash of the whole UID.
    pub fn from_uid(uid: &str) -> Self {
        let bytes = uid.as_bytes();
        let mut uid_suffix = [0u8; UID_SUFFIX_LEN];
        if bytes.len() >= UID_SUFFIX_LEN {
            uid_suffix.copy_from_slice(&bytes[bytes.len() - UID_SUFFIX_LEN..]);
        } else {
            uid_suffix[..bytes.len()].copy_from_slice(bytes);
        }
        Self {
            uid_suffix,
            uid_hash: lookup3::uid_to_u64(bytes),
        }
    }

    pub fn uid_suffix(&self) -> &[u8; 64] {
        &self.uid_suffix
    }

    pub fn uid_hash(&self) -> u64 {
        self.uid_hash
    }
}

impl std::fmt::Debug for PodKey {
    /// The suffix is a UID string padded with NULs; show it as text so a
    /// failing assertion is readable.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let end = self
            .uid_suffix
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(self.uid_suffix.len());
        f.debug_struct("PodKey")
            .field(
                "uid_suffix",
                &String::from_utf8_lossy(&self.uid_suffix[..end]),
            )
            .field("uid_hash", &self.uid_hash)
            .finish()
    }
}

/// The matching-app `k8s_pod` span's fields.
#[derive(Debug, Clone, Default)]
pub struct K8sPodData {
    pub key: PodKey,
    pub owner_name: String,
    pub owner_uid: String,
    pub pod_name: String,
    pub ns: String,
    pub version: String,
}

impl Default for PodKey {
    fn default() -> Self {
        Self {
            uid_suffix: [0u8; 64],
            uid_hash: 0,
        }
    }
}

/// The matching-app `k8s_container` span's fields, including its reference to
/// the owning pod.
#[derive(Debug, Clone, Default)]
pub struct K8sContainerData {
    pub key: PodKey,
    pub name: String,
    pub version: String,
    pub pod: Option<PodKey>,
}

/// The matching-app `aws_enrichment` span's payload (`AwsEnrichmentInfo`).
#[derive(Debug, Clone, Default)]
pub struct AwsInfo {
    pub role: String,
    pub az: String,
    pub id: String,
}

/// The `flow` span's index tuple `(addr1, port1, addr2, port2)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub addr1: u128,
    pub port1: u16,
    pub addr2: u128,
    pub port2: u16,
}

struct Entry<V> {
    value: V,
    /// How many live `(queue, reference)` handles point here.
    ref_count: u32,
}

/// A bounded, key-indexed span pool with per-queue reference tables.
///
/// `V` is created lazily on the first `_start` for a key, and dropped when the
/// last reference to it ends — the lifecycle the generated pool implements.
pub struct Pool<K: Eq + Hash + Clone, V> {
    entries: HashMap<K, Entry<V>>,
    /// `(queue index, wire reference) -> key`. Two ingest queues may hand out
    /// the same reference number for different spans, so the queue is part of
    /// the handle.
    refs: HashMap<(usize, u64), K>,
    capacity: usize,
}

impl<K: Eq + Hash + Clone, V> Pool<K, V> {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            refs: HashMap::new(),
            capacity,
        }
    }

    /// Live spans (not handles).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Live `(queue, reference)` handles.
    pub fn reference_count(&self) -> usize {
        self.refs.len()
    }

    /// Handles a `_start`: binds `(queue, reference)` to `key`, creating the
    /// span with `make` if this is the first reference to it.
    ///
    /// Rebinding a live handle to a different key releases the old one first —
    /// the ingest core reuses a reference number after ending it, and a lost
    /// `_end` must not pin a span forever.
    pub fn start(
        &mut self,
        queue: usize,
        reference: u64,
        key: K,
        make: impl FnOnce() -> V,
    ) -> Result<&mut V, PoolError> {
        if let Some(previous) = self.refs.get(&(queue, reference)) {
            if *previous == key {
                // Duplicate start for a handle we already hold: no double count.
                return Ok(&mut self
                    .entries
                    .get_mut(&key)
                    .expect("live reference implies a live entry")
                    .value);
            }
            let previous = previous.clone();
            self.release(&previous);
        }

        // Capacity is read before the entry borrow: a vacant entry already
        // holds the map mutably.
        let at_capacity = self.entries_at_capacity_hint();

        match self.entries.entry(key.clone()) {
            MapEntry::Occupied(occupied) => {
                occupied.into_mut().ref_count += 1;
            }
            MapEntry::Vacant(vacant) => {
                if at_capacity {
                    return Err(PoolError::Exhausted);
                }
                vacant.insert(Entry {
                    value: make(),
                    ref_count: 1,
                });
            }
        }

        self.refs.insert((queue, reference), key.clone());
        Ok(&mut self.entries.get_mut(&key).expect("just inserted").value)
    }

    /// Whether inserting one more span would exceed the render `pool_size`.
    fn entries_at_capacity_hint(&self) -> bool {
        self.entries.len() >= self.capacity
    }

    /// Handles an `_end`: drops the handle, and the span with it when this was
    /// its last reference. Returns whether the handle existed.
    pub fn end(&mut self, queue: usize, reference: u64) -> bool {
        match self.refs.remove(&(queue, reference)) {
            Some(key) => {
                self.release(&key);
                true
            }
            None => false,
        }
    }

    fn release(&mut self, key: &K) {
        if let MapEntry::Occupied(mut occupied) = self.entries.entry(key.clone()) {
            let entry = occupied.get_mut();
            entry.ref_count = entry.ref_count.saturating_sub(1);
            if entry.ref_count == 0 {
                occupied.remove();
            }
        }
    }

    /// The span a wire message is addressed to.
    pub fn by_ref_mut(&mut self, queue: usize, reference: u64) -> Option<&mut V> {
        let key = self.refs.get(&(queue, reference))?.clone();
        self.entries.get_mut(&key).map(|entry| &mut entry.value)
    }

    /// The key a handle resolves to.
    pub fn key_of(&self, queue: usize, reference: u64) -> Option<&K> {
        self.refs.get(&(queue, reference))
    }

    pub fn by_key(&self, key: &K) -> Option<&V> {
        self.entries.get(key).map(|entry| &entry.value)
    }

    pub fn by_key_mut(&mut self, key: &K) -> Option<&mut V> {
        self.entries.get_mut(key).map(|entry| &mut entry.value)
    }

    /// Iterates every live span, for the timeslot flush.
    pub fn values_mut(&mut self) -> impl Iterator<Item = (&K, &mut V)> {
        self.entries
            .iter_mut()
            .map(|(key, entry)| (key, &mut entry.value))
    }
}

/// Read-only view of the enrichment tables, as node resolution needs them.
///
/// Borrowing the three pools separately lets the caller hold the flow table
/// mutably at the same time.
pub struct SpanTables<'a> {
    pub pods: &'a Pool<PodKey, K8sPodData>,
    pub containers: &'a Pool<PodKey, K8sContainerData>,
    pub aws: &'a Pool<u128, AwsInfo>,
}

impl SpanTables<'_> {
    pub fn pod_by_key(&self, key: &PodKey) -> Option<&K8sPodData> {
        self.pods.by_key(key)
    }

    /// The container a cgroup-derived container id names.
    pub fn container_by_id(&self, container_id: &str) -> Option<&K8sContainerData> {
        self.containers.by_key(&PodKey::from_uid(container_id))
    }

    /// The AWS enrichment span covering an address, if one was reported.
    pub fn aws_by_ip(&self, addr: &IPv6Address) -> Option<&AwsInfo> {
        self.aws.by_key(&addr.as_int())
    }
}

/// `DockerImageMetadata::version`: the tag or checksum of an image reference.
///
/// ```text
/// registry/name:tag          -> tag
/// registry/name@sha256:abcd  -> sha256:abcd
/// sha256:abcd                -> sha256:abcd   (whole thing; it is not a name)
/// name                       -> ""
/// ```
pub fn image_version(image: &str) -> &str {
    // The registry is everything up to the last '/', and never contains the
    // version, so strip it before looking for delimiters.
    let rest = match image.rfind('/') {
        Some(i) => &image[i + 1..],
        None => image,
    };

    if let Some(i) = rest.find('@') {
        return &rest[i + 1..];
    }

    match rest.find(':') {
        // A bare "sha256:..." is a checksum, not a name and tag.
        Some(i) if &rest[..i] == "sha256" => rest,
        Some(i) => &rest[i + 1..],
        None => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool() -> Pool<u32, String> {
        Pool::new(2)
    }

    /// A key is created on first start and found by later messages on the
    /// same handle.
    #[test]
    fn start_creates_and_binds_a_reference() {
        let mut p = pool();
        p.start(0, 7, 100, || "first".to_string()).expect("start");

        assert_eq!(p.by_ref_mut(0, 7).map(|v| v.as_str()), Some("first"));
        assert_eq!(p.len(), 1);
    }

    /// The same reference number on two queues addresses two different spans.
    #[test]
    fn references_are_scoped_per_queue() {
        let mut p = pool();
        p.start(0, 1, 100, || "queue zero".to_string()).unwrap();
        p.start(1, 1, 200, || "queue one".to_string()).unwrap();

        assert_eq!(p.by_ref_mut(0, 1).map(|v| v.as_str()), Some("queue zero"));
        assert_eq!(p.by_ref_mut(1, 1).map(|v| v.as_str()), Some("queue one"));
        assert_eq!(p.len(), 2);
    }

    /// Two agents on one flow share the span; it survives the first `_end`
    /// and dies on the second.
    #[test]
    fn span_lives_until_the_last_reference_ends() {
        let mut p = pool();
        p.start(0, 1, 100, || "shared".to_string()).unwrap();
        p.start(1, 5, 100, || panic!("must reuse the existing span"))
            .unwrap();
        assert_eq!(p.len(), 1);

        assert!(p.end(0, 1));
        assert_eq!(p.len(), 1, "one reference still holds the span");

        assert!(p.end(1, 5));
        assert_eq!(p.len(), 0);
        assert_eq!(p.reference_count(), 0);
    }

    /// Reusing a live reference number for another key releases the old span,
    /// so a lost `_end` cannot pin it forever.
    #[test]
    fn rebinding_a_reference_releases_the_previous_span() {
        let mut p = pool();
        p.start(0, 1, 100, || "old".to_string()).unwrap();
        p.start(0, 1, 200, || "new".to_string()).unwrap();

        assert_eq!(p.len(), 1);
        assert_eq!(p.by_ref_mut(0, 1).map(|v| v.as_str()), Some("new"));
    }

    /// A repeated start on the same handle and key must not inflate the count.
    #[test]
    fn duplicate_start_does_not_double_count() {
        let mut p = pool();
        p.start(0, 1, 100, || "once".to_string()).unwrap();
        p.start(0, 1, 100, || panic!("must not rebuild")).unwrap();

        assert!(p.end(0, 1));
        assert_eq!(p.len(), 0, "one end must release a singly-started span");
    }

    /// At `pool_size` a new key is refused — and the pool keeps working for
    /// keys it already holds.
    #[test]
    fn start_reports_exhaustion_at_capacity() {
        let mut p = pool();
        p.start(0, 1, 100, || "a".to_string()).unwrap();
        p.start(0, 2, 200, || "b".to_string()).unwrap();

        assert_eq!(
            p.start(0, 3, 300, || "c".to_string()).unwrap_err(),
            PoolError::Exhausted
        );
        assert_eq!(p.len(), 2);
        assert!(p.by_ref_mut(0, 3).is_none(), "refused start binds nothing");

        // An existing key still accepts new references.
        p.start(0, 4, 100, || panic!("must reuse")).unwrap();
        assert_eq!(p.by_ref_mut(0, 4).map(|v| v.as_str()), Some("a"));
    }

    /// Freeing a span makes room again.
    #[test]
    fn ending_a_span_frees_capacity() {
        let mut p = pool();
        p.start(0, 1, 100, || "a".to_string()).unwrap();
        p.start(0, 2, 200, || "b".to_string()).unwrap();
        assert!(p.end(0, 1));

        p.start(0, 3, 300, || "c".to_string())
            .expect("capacity freed by the end");
        assert_eq!(p.len(), 2);
    }

    /// An `_end` for a handle that was never started is reported, not panicked.
    #[test]
    fn ending_an_unknown_reference_is_reported() {
        let mut p = pool();
        assert!(!p.end(0, 42));
    }

    /// A short UID is zero-padded; a long one keeps its last 64 bytes. Both
    /// hash the whole UID, so the key still separates them.
    #[test]
    fn uid_key_pads_short_and_truncates_long_uids() {
        let short = PodKey::from_uid("abc");
        assert_eq!(&short.uid_suffix()[..3], b"abc");
        assert!(short.uid_suffix()[3..].iter().all(|b| *b == 0));

        let long: String = std::iter::repeat('x').take(70).collect();
        let long_key = PodKey::from_uid(&long);
        assert!(long_key.uid_suffix().iter().all(|b| *b == b'x'));

        let other: String = std::iter::repeat('x').take(80).collect();
        assert_ne!(
            long_key.uid_hash(),
            PodKey::from_uid(&other).uid_hash(),
            "identical suffixes must still be separated by the hash"
        );
    }

    #[test]
    fn image_version_extracts_tag_checksum_or_nothing() {
        assert_eq!(image_version("quay.io/otel/collector:v1.2.3"), "v1.2.3");
        assert_eq!(image_version("collector:v1.2.3"), "v1.2.3");
        assert_eq!(image_version("collector"), "");
        assert_eq!(
            image_version("quay.io/otel/collector@sha256:deadbeef"),
            "sha256:deadbeef"
        );
        assert_eq!(image_version("sha256:deadbeef"), "sha256:deadbeef");
        // A registry with a port must not be mistaken for a tag.
        assert_eq!(image_version("registry:5000/collector"), "");
    }
}
