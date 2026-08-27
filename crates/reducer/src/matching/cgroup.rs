//! Port of `util/cgroup_parser.{h,cc}`.
//!
//! The matching core reads a task's cgroup name to recover the container id
//! that keys the `k8s_container` table, and (indirectly) the pod behind it. The
//! parse must agree with the C++ one character for character: the container id
//! it yields is hashed into a `(uid_suffix, uid_hash)` key and compared against
//! keys the ingest core produced, so a parse that stops one character early
//! resolves nothing rather than resolving wrongly.
//!
//! Three cgroup shapes appear in practice, tried in the C++ order:
//!
//! ```text
//! systemd:  kubepods-burstable-pod146bb920_a47b_4f6c_a69a_166b63944d15.slice:cri-containerd:c45f...
//! cri:      cri-containerd-15736ea91752be37a640dc949e3e805521f4af5c5e3fe50643af0e63a5ce0df5.scope
//! bare:     6f652f89943b50f7b101d13f11371daf34bf836b7e1b725b5e8b6439451018bd
//! service:  systemd-journald.service
//! ```

/// What a cgroup name yields. Fields left empty when the shape does not carry
/// them, mirroring `CGroupInfo`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CGroupInfo {
    /// 64 hex characters identifying the container.
    pub container_id: String,
    /// Container runtime, e.g. `containerd`.
    pub runtime: String,
    /// Pod UID in canonical `8-4-4-4-12` form, whatever separators the source
    /// used.
    pub pod_id: String,
    /// Kubernetes QoS class: `guaranteed`, `besteffort`, or `burstable`.
    pub qos: String,
    /// systemd service name, for `*.service` cgroups.
    pub service: String,
    /// Whether any shape matched. A false here means every field is empty.
    pub valid: bool,
}

/// Cursor over the cgroup name. Every `parse_*` either consumes its token and
/// returns true, or leaves the cursor where it found it and returns false —
/// the same backtracking discipline as the C++ `parse_*` helpers, which rely
/// on their callers not retrying a failed branch from a moved read head.
struct Cursor<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input: input.as_bytes(),
            pos: 0,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    /// Consumes `literal` when it is next.
    fn match_literal(&mut self, literal: &str) -> bool {
        let end = self.pos + literal.len();
        if end <= self.input.len() && &self.input[self.pos..end] == literal.as_bytes() {
            self.pos = end;
            return true;
        }
        false
    }

    /// Consumes one hex digit, appending it to `out`.
    fn match_hex_digit(&mut self, out: &mut String) -> bool {
        match self.peek() {
            Some(c) if c.is_ascii_hexdigit() => {
                out.push(c as char);
                self.pos += 1;
                true
            }
            _ => false,
        }
    }

    /// Consumes up to and including the next `token`, yielding the text before
    /// it. `parse_token` in the C++: false when the token is absent.
    fn match_token(&mut self, token: u8) -> Option<String> {
        let rest = &self.input[self.pos..];
        let at = rest.iter().position(|c| *c == token)?;
        let value = String::from_utf8_lossy(&rest[..at]).into_owned();
        self.pos += at + 1;
        Some(value)
    }
}

/// Parses a cgroup name, as `CGroupParser`'s constructor does.
pub fn parse(cgroup_name: &str) -> CGroupInfo {
    let mut info = CGroupInfo::default();
    let mut cursor = Cursor::new(cgroup_name);

    // One cursor across all alternatives, as `parse_cgroup` does: a failed
    // branch leaves the read head wherever it stopped, and the next branch
    // resumes from there rather than restarting.
    info.valid = parse_systemd(&mut cursor, &mut info)
        || parse_cri(&mut cursor, &mut info)
        || parse_pod_id(&mut cursor, &mut info)
        || parse_container_id(&mut cursor, &mut info)
        || parse_service(cgroup_name, &mut info);

    info
}

/// `kubepods-<qos>[-pod<uid>[.slice:<runtime>:<container id>]]`.
///
/// Each optional tail is "done and valid" in the C++, so a truncated systemd
/// cgroup still yields the fields it did carry.
fn parse_systemd(cursor: &mut Cursor<'_>, info: &mut CGroupInfo) -> bool {
    if !cursor.match_literal("kubepods-") {
        return false;
    }
    if !parse_qos(cursor, info) {
        return false;
    }

    // Skip to the next separator: ".slice:..." carries nothing we want here.
    cursor.match_token(b'-');

    if !parse_pod_id(cursor, info) {
        return true;
    }
    cursor.match_token(b'-');

    if !parse_runtime(cursor, info, b':') {
        return true;
    }
    parse_container_id(cursor, info);
    true
}

/// `cri-<runtime>-<container id>.scope`.
fn parse_cri(cursor: &mut Cursor<'_>, info: &mut CGroupInfo) -> bool {
    cursor.match_literal("cri-")
        && parse_runtime(cursor, info, b'-')
        && parse_container_id(cursor, info)
}

/// Exactly 64 hex characters. On failure the partial id is discarded, so a
/// caller never sees a half-parsed container id.
fn parse_container_id(cursor: &mut Cursor<'_>, info: &mut CGroupInfo) -> bool {
    let mut id = String::with_capacity(64);
    for _ in 0..64 {
        if !cursor.match_hex_digit(&mut id) {
            info.container_id.clear();
            return false;
        }
    }
    info.container_id = id;
    true
}

/// `pod<uid>`, normalising the UID to canonical `8-4-4-4-12` form.
fn parse_pod_id(cursor: &mut Cursor<'_>, info: &mut CGroupInfo) -> bool {
    if !cursor.match_literal("pod") {
        return false;
    }
    parse_uid(cursor, info)
}

/// The UID groups, accepting `-`, `_`, or no separator between them and always
/// emitting `-`.
fn parse_uid(cursor: &mut Cursor<'_>, info: &mut CGroupInfo) -> bool {
    let mut uid = String::new();
    for group in [8usize, 4, 4, 4, 12] {
        for _ in 0..group {
            if !cursor.match_hex_digit(&mut uid) {
                return false;
            }
        }
        if group == 12 {
            break;
        }
        match cursor.peek() {
            None => return false,
            Some(c) => {
                if c == b'-' || c == b'_' {
                    cursor.pos += 1;
                }
            }
        }
        uid.push('-');
    }
    info.pod_id = uid;
    true
}

/// Kubernetes QoS class, in the C++ probe order.
fn parse_qos(cursor: &mut Cursor<'_>, info: &mut CGroupInfo) -> bool {
    for qos in ["guaranteed", "besteffort", "burstable"] {
        if cursor.match_literal(qos) {
            info.qos = qos.to_string();
            return true;
        }
    }
    false
}

/// Runtime name, up to `token`. Not validated against a known set, matching the
/// C++.
fn parse_runtime(cursor: &mut Cursor<'_>, info: &mut CGroupInfo, token: u8) -> bool {
    match cursor.match_token(token) {
        Some(runtime) => {
            info.runtime = runtime;
            true
        }
        None => false,
    }
}

/// A `*.service` cgroup, recognised by suffix alone.
fn parse_service(cgroup_name: &str, info: &mut CGroupInfo) -> bool {
    const SERVICE_SUFFIX: &str = ".service";
    match cgroup_name.strip_suffix(SERVICE_SUFFIX) {
        Some(service) => {
            info.service = service.to_string();
            true
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The full systemd shape carries every field.
    #[test]
    fn systemd_cgroup_with_container() {
        let info = parse(
            "kubepods-burstable-pod146bb920_a47b_4f6c_a69a_166b63944d15.slice:cri-containerd:\
             c45f3e9c19746eabf0a4af63d780ba5c2a657a7352c7ad7acc5d599da5115eef",
        );
        assert!(info.valid);
        assert_eq!(info.qos, "burstable");
        assert_eq!(info.pod_id, "146bb920-a47b-4f6c-a69a-166b63944d15");
        // The C++ eats up to and including the next '-' before reading the
        // runtime, which swallows the ".slice:cri-" prefix: the runtime is
        // "containerd", not "cri-containerd".
        assert_eq!(info.runtime, "containerd");
        assert_eq!(
            info.container_id,
            "c45f3e9c19746eabf0a4af63d780ba5c2a657a7352c7ad7acc5d599da5115eef"
        );
    }

    /// A systemd cgroup that stops after the pod is still valid, with no
    /// container id — the case that decides whether a flow can be enriched to
    /// a container or only to a pod.
    #[test]
    fn systemd_cgroup_without_container() {
        let info = parse("kubepods-besteffort-pod29c71929_0064_4c15_9595_702c5931a368.slice");
        assert!(info.valid);
        assert_eq!(info.qos, "besteffort");
        assert_eq!(info.pod_id, "29c71929-0064-4c15-9595-702c5931a368");
        assert!(info.container_id.is_empty());
    }

    #[test]
    fn cri_cgroup_yields_runtime_and_container() {
        let info = parse(
            "cri-containerd-15736ea91752be37a640dc949e3e805521f4af5c5e3fe50643af0e63a5ce0df5.scope",
        );
        assert!(info.valid);
        assert_eq!(info.runtime, "containerd");
        assert_eq!(
            info.container_id,
            "15736ea91752be37a640dc949e3e805521f4af5c5e3fe50643af0e63a5ce0df5"
        );
    }

    #[test]
    fn bare_container_id_is_recognised() {
        let id = "6f652f89943b50f7b101d13f11371daf34bf836b7e1b725b5e8b6439451018bd";
        let info = parse(id);
        assert!(info.valid);
        assert_eq!(info.container_id, id);
    }

    /// Both cgroupfs (`-`) and separator-free pod UIDs normalise to the same
    /// canonical string the pod table is keyed on.
    #[test]
    fn pod_uid_separators_normalise() {
        let dashed = parse("podf55fb707-9bf6-4bf5-8a7e-19c5f3e52215");
        let bare = parse("podf55fb7079bf64bf58a7e19c5f3e52215");
        assert_eq!(dashed.pod_id, "f55fb707-9bf6-4bf5-8a7e-19c5f3e52215");
        assert_eq!(bare.pod_id, "f55fb707-9bf6-4bf5-8a7e-19c5f3e52215");
    }

    #[test]
    fn service_cgroup_is_recognised_by_suffix() {
        let info = parse("systemd-journald.service");
        assert!(info.valid);
        assert_eq!(info.service, "systemd-journald");
        assert!(info.container_id.is_empty());
    }

    /// A short hex string is not a container id: the partial parse must not
    /// leak into `container_id`, or it would key the container table on a
    /// truncated value.
    #[test]
    fn truncated_container_id_is_rejected_without_partial_output() {
        let info = parse("6f652f89943b50f7");
        assert!(!info.valid);
        assert!(info.container_id.is_empty());
    }

    #[test]
    fn unrecognised_cgroup_is_invalid() {
        let info = parse("user.slice");
        assert!(!info.valid);
        assert_eq!(info, CGroupInfo::default());
    }
}
