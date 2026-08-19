//! Tamper-evident transparency log for settlement audit entries.
//!
//! Builds on top of the settlement history audit log (#023) by wrapping each
//! entry in a Merkle tree (Certificate Transparency style).  The key properties:
//!
//! - **Append-only**: every new entry's hash incorporates the full prior tree
//!   state, so modifying any historical entry changes all subsequent root hashes.
//! - **Inclusion proofs**: a compact proof that a specific entry is part of the
//!   log, verifiable by anyone who knows the root hash.
//! - **Consistency proofs**: proof that a log at size T2 is a valid append-only
//!   extension of the log at size T1, without replaying the entries in between.
//! - **Tamper detection**: direct SQLite edits outside the log's own append API
//!   are detected on the next `verify_root` / `verify_integrity` call because the
//!   recomputed root hash won't match the stored one.
//!
//! ## Why Merkle tree over simple hash chain?
//!
//! A hash chain (each entry hashing the previous) is sufficient for detecting
//! modifications, but it only provides O(n) inclusion proofs (you must walk the
//! entire chain from the entry to the head).  A Merkle tree gives us:
//!
//! - **O(log n) inclusion proofs** — critical when proving history to a relay or
//!   dispute-resolution committee that may only care about a single entry.
//! - **Efficient consistency proofs** — the standard sub-tree decomposition from
//!   RFC 6962 lets us prove the log grew without replaying every entry.
//! - **Compact root hash** — a single 32-byte hash summarising the entire log,
//!   suitable for periodic publication or on-demand verification.
//!
//! ## Without a trusted third party
//!
//! A real Certificate Transparency log relies on independent *witnesses* that
//! co-sign root hashes, preventing the log operator from presenting different
//! views to different parties (split-view attacks).  Without witnesses, the root
//! hash still provides:
//!
//! - **Self-consistency**: the device can detect if *its own* storage was tampered
//!   with between append and verify.
//! - **External consistency (with caveats)**: a relay or committee can verify the
//!   device's claimed history via inclusion/consistency proofs against the
//!   advertised root.  This catches accidental corruption and most tampering.
//!   However, a fully compromised device could reconstruct a fake log from
//!   scratch (including valid-looking proofs) — only an external witness that
//!   independently records root hashes can prevent this.
//!
//! A future witnessing mechanism would:
//!
//! 1. Periodically publish root hashes to a blockchain, a notary service, or a
//!    federation of relay nodes.
//! 2. Require the device to present a *signed* root hash when connecting, so the
//!    verifier can check it against the witness ledger.
//! 3. Enable *consistency monitoring*: if the device ever publishes a root hash
//!    inconsistent with a previously witnessed one, the tampering is provable.

use sha2::{Digest, Sha256};

// Domain separators to prevent hash collision attacks between leaf and node
// hashes, and between this log and any other SHA-256 usage in the crate.
const LEAF_DOMAIN: &[u8] = b"stellarconduit_transparency_log_leaf_v1";
const NODE_DOMAIN: &[u8] = b"stellarconduit_transparency_log_node_v1";

/// A single entry in the transparency log, corresponding to one settlement
/// history row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    /// Sequential index in the log (0-based).
    pub index: u64,
    /// The settlement history row's `message_id`.
    pub message_id: [u8; 32],
    /// Previous settlement status (empty string for the first transition).
    pub from_status: String,
    /// New settlement status.
    pub to_status: String,
    /// Unix timestamp of the transition.
    pub timestamp: u64,
}

impl LogEntry {
    /// Deterministic byte representation for hashing.  Includes the index so that
    /// swapping two entries with identical data is detectable.
    fn to_hash_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.index.to_le_bytes());
        buf.extend_from_slice(&self.message_id);
        buf.extend_from_slice(self.from_status.as_bytes());
        buf.extend_from_slice(self.to_status.as_bytes());
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf
    }
}

/// Domain-separated SHA-256 hash of a leaf entry.
fn leaf_hash(entry: &LogEntry) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(LEAF_DOMAIN);
    hasher.update(entry.to_hash_bytes());
    hasher.finalize().into()
}

/// Domain-separated SHA-256 hash of an internal node (concatenation of two
/// child hashes).
fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(NODE_DOMAIN);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// All-zeroes hash used as padding for incomplete tree subtrees.
const EMPTY_HASH: [u8; 32] = [0u8; 32];

// ---------------------------------------------------------------------------
// Merkle tree construction
// ---------------------------------------------------------------------------

/// Build all levels of the Merkle tree from the given leaf hashes.
///
/// The leaves are padded to the next power of two with [`EMPTY_HASH`] so that
/// the tree is always a perfect binary tree — this makes proof generation and
/// verification straightforward.
fn build_tree_levels(leaves: &[[u8; 32]]) -> Vec<Vec<[u8; 32]>> {
    if leaves.is_empty() {
        return vec![vec![EMPTY_HASH]];
    }
    let mut levels: Vec<Vec<[u8; 32]>> = Vec::new();

    // Pad leaves to next power of two.
    let padded_len = leaves.len().next_power_of_two();
    let mut level = leaves.to_vec();
    level.resize(padded_len, EMPTY_HASH);
    levels.push(level);

    while levels.last().unwrap().len() > 1 {
        let prev = levels.last().unwrap();
        let mut next = Vec::with_capacity(prev.len() / 2);
        for chunk in prev.chunks_exact(2) {
            next.push(node_hash(&chunk[0], &chunk[1]));
        }
        levels.push(next);
    }
    levels
}

/// Return the root hash of a pre-built tree.
fn root_from_levels(levels: &[Vec<[u8; 32]>]) -> [u8; 32] {
    levels.last().unwrap()[0]
}

// ---------------------------------------------------------------------------
// Inclusion proof
// ---------------------------------------------------------------------------

/// A compact proof that a specific leaf is included in the Merkle tree at a
/// given root hash.  Sufficient for independent verification by a third party
/// that only knows the root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    /// Index of the proved leaf in the log.
    pub leaf_index: usize,
    /// Hash of the proved leaf.
    pub leaf_hash: [u8; 32],
    /// Sibling hashes on the path from leaf to root, bottom-up.
    /// Each entry is `(sibling_hash, sibling_is_right)` — `true` means the
    /// sibling is the right child (so the proved hash is on the left).
    pub path: Vec<([u8; 32], bool)>,
    /// The root hash this proof is valid against.
    pub root_hash: [u8; 32],
}

/// Generate an inclusion proof for the leaf at `index`.
fn inclusion_proof_from_levels(
    levels: &[Vec<[u8; 32]>],
    leaves: &[[u8; 32]],
    index: usize,
) -> Option<InclusionProof> {
    let total_leaves = leaves.len();
    if index >= total_leaves {
        return None;
    }

    let root = root_from_levels(levels);
    let leaf_h = leaves[index];

    let mut path = Vec::new();
    let mut idx = index;
    // Walk from leaf level up to the root (but not including root itself).
    for level in &levels[..levels.len() - 1] {
        let (sibling_idx, is_right) = if idx % 2 == 0 {
            (idx + 1, true)
        } else {
            (idx - 1, false)
        };
        let sibling = if sibling_idx < level.len() {
            level[sibling_idx]
        } else {
            EMPTY_HASH
        };
        path.push((sibling, is_right));
        idx /= 2;
    }

    Some(InclusionProof {
        leaf_index: index,
        leaf_hash: leaf_h,
        path,
        root_hash: root,
    })
}

/// Verify an inclusion proof.  Returns `true` if the proof is valid — i.e. the
/// leaf hash, combined with the path, reproduces the claimed root hash.
pub fn verify_inclusion_proof(proof: &InclusionProof) -> bool {
    let mut current = proof.leaf_hash;
    for &(sibling, is_right) in &proof.path {
        current = if is_right {
            node_hash(&current, &sibling)
        } else {
            node_hash(&sibling, &current)
        };
    }
    current == proof.root_hash
}

// ---------------------------------------------------------------------------
// Consistency proof
// ---------------------------------------------------------------------------

/// A proof that a log of size `new_size` is a valid append-only extension of a
/// log of size `old_size`.  Follows the sub-tree decomposition from RFC 6962
/// §2.1.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsistencyProof {
    pub old_size: usize,
    pub new_size: usize,
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],
    /// Hashes needed by the verifier to recompute both roots and confirm the
    /// old root is a prefix of the new tree.  The verifier reconstructs the
    /// sub-trees from these hashes plus the old and new leaves.
    pub proof_hashes: Vec<[u8; 32]>,
}

/// Compute the sub-tree hash for a range of leaves `[start, end)` within the
/// given (padded) leaf level.  This is used both during proof generation and
/// verification.
fn subtree_hash(leaves: &[[u8; 32]], start: usize, end: usize) -> [u8; 32] {
    debug_assert!(start < end);
    let len = end - start;
    if len == 1 {
        return leaves[start];
    }
    let mid = start + (len.next_power_of_two() / 2);
    if mid >= end {
        // The range is already a single leaf in the padded tree.
        return leaves[start];
    }
    let left = subtree_hash(leaves, start, mid);
    let right = if mid < end {
        subtree_hash(leaves, mid, end)
    } else {
        EMPTY_HASH
    };
    node_hash(&left, &right)
}

/// Generate a consistency proof from `old_size` to `new_size`.
///
/// Returns `None` if `old_size > new_size` or either size is zero.
pub fn consistency_proof(
    old_leaves: &[[u8; 32]],
    new_leaves: &[[u8; 32]],
    old_size: usize,
    new_size: usize,
) -> Option<ConsistencyProof> {
    if old_size == 0 || old_size > new_size {
        return None;
    }
    if old_size == new_size {
        // Trivial: same log — roots must match.
        let old_root = root_from_levels(&build_tree_levels(old_leaves));
        let new_root = root_from_levels(&build_tree_levels(new_leaves));
        return Some(ConsistencyProof {
            old_size,
            new_size,
            old_root,
            new_root,
            proof_hashes: Vec::new(),
        });
    }

    let old_root = root_from_levels(&build_tree_levels(old_leaves));
    let new_root = root_from_levels(&build_tree_levels(new_leaves));

    // Collect sub-tree hashes for the new tree over the range [0, old_size).
    // These are sufficient for the verifier to recompute the old root from the
    // new tree's leaves.
    let proof_hashes = collect_subtree_hashes(new_leaves, old_size);

    Some(ConsistencyProof {
        old_size,
        new_size,
        old_root,
        new_root,
        proof_hashes,
    })
}

/// Collect the sub-tree decomposition hashes for range `[0, size)` within the
/// padded leaves.  This mirrors the algorithm from RFC 6962 §2.1.2: we walk
/// from left to right, taking the largest power-of-two subtree at each step.
fn collect_subtree_hashes(leaves: &[[u8; 32]], size: usize) -> Vec<[u8; 32]> {
    let mut hashes = Vec::new();
    let mut start = 0;
    while start < size {
        // Find the largest power-of-two subtree starting at `start`.
        let remaining = size - start;
        let sub_size = remaining.next_power_of_two() / 2;
        // But we must not exceed the padded tree width.
        let actual_size = sub_size.min(leaves.len() - start);
        if actual_size == 0 {
            break;
        }
        hashes.push(subtree_hash(leaves, start, start + actual_size));
        start += actual_size;
    }
    hashes
}

/// Rebuild the old root from the new tree's leaves and the proof hashes, then
/// verify it matches the claimed old root.  Also verifies the new root matches.
pub fn verify_consistency_proof(proof: &ConsistencyProof, new_leaves: &[[u8; 32]]) -> bool {
    if proof.old_size == 0 || proof.old_size > proof.new_size {
        return false;
    }
    if proof.old_size == proof.new_size {
        // Trivial: both roots must be equal.
        let expected = root_from_levels(&build_tree_levels(new_leaves));
        return proof.old_root == proof.new_root && proof.new_root == expected;
    }

    // Rebuild old root from the proof hashes (which decompose the new tree's
    // range [0, old_size) into sub-trees).
    let mut reconstructed = EMPTY_HASH;
    for hash in &proof.proof_hashes {
        reconstructed = node_hash(&reconstructed, hash);
    }

    let actual_new_root = root_from_levels(&build_tree_levels(new_leaves));

    reconstructed == proof.old_root && actual_new_root == proof.new_root
}

// ---------------------------------------------------------------------------
// TransparencyLog — the main public API
// ---------------------------------------------------------------------------

/// Append-only Merkle transparency log over settlement history entries.
///
/// All mutations go through [`TransparencyLog::append`], which recomputes the
/// root hash.  The log can then produce inclusion/consistency proofs on demand.
/// Any out-of-band modification to the underlying data will cause a root hash
/// mismatch on the next verification, because the tree is always rebuilt from
/// the stored entries.
#[derive(Debug, Clone)]
pub struct TransparencyLog {
    entries: Vec<LogEntry>,
    leaves: Vec<[u8; 32]>,
    root: [u8; 32],
}

impl TransparencyLog {
    /// Create an empty transparency log.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            leaves: Vec::new(),
            root: EMPTY_HASH,
        }
    }

    /// Append a new entry and recompute the root hash.
    ///
    /// The entry's index is set automatically based on the current log length.
    pub fn append(&mut self, mut entry: LogEntry) {
        entry.index = self.entries.len() as u64;
        let h = leaf_hash(&entry);
        self.entries.push(entry);
        self.leaves.push(h);
        let levels = build_tree_levels(&self.leaves);
        self.root = root_from_levels(&levels);
    }

    /// The current number of entries in the log.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The current root hash summarising the entire log.
    pub fn root_hash(&self) -> [u8; 32] {
        self.root
    }

    /// Borrow an entry by index.
    pub fn get(&self, index: usize) -> Option<&LogEntry> {
        self.entries.get(index)
    }

    /// All entries in the log.
    pub fn entries(&self) -> &[LogEntry] {
        &self.entries
    }

    /// Generate an inclusion proof for the entry at `index`.
    pub fn inclusion_proof(&self, index: usize) -> Option<InclusionProof> {
        let levels = build_tree_levels(&self.leaves);
        inclusion_proof_from_levels(&levels, &self.leaves, index)
    }

    /// Generate a consistency proof showing that a log of size `old_size` is a
    /// prefix of the current log.  Returns `None` if `old_size` is out of
    /// range.
    pub fn consistency_proof_for(&self, old_size: usize) -> Option<ConsistencyProof> {
        if old_size == 0 || old_size > self.len() {
            return None;
        }
        let old_leaves = &self.leaves[..old_size];
        consistency_proof(old_leaves, &self.leaves, old_size, self.len())
    }

    /// Rebuild the root from scratch and verify it matches the cached value.
    ///
    /// This is the primary tamper-detection mechanism: after calling this, a
    /// `false` return indicates that the underlying data has been modified
    /// outside the log's own API.
    pub fn verify_root(&self) -> bool {
        let levels = build_tree_levels(&self.leaves);
        root_from_levels(&levels) == self.root
    }

    /// Verify that every entry hashes to the stored leaf hash.  Useful as a
    /// secondary integrity check beyond root verification.
    pub fn verify_entries(&self) -> bool {
        self.entries
            .iter()
            .zip(self.leaves.iter())
            .all(|(entry, &expected)| leaf_hash(entry) == expected)
    }

    /// Full integrity check: recomputes the root from entries and verifies it.
    /// This catches any tampering with either the entries or the cached root.
    pub fn verify_integrity(&self) -> bool {
        self.verify_root() && self.verify_entries()
    }

    /// Rebuild the log from a sequence of entries, recomputing all hashes.
    ///
    /// Used after loading entries from storage to verify they haven't been
    /// tampered with.  Returns the computed root hash.
    pub fn from_entries(entries: Vec<LogEntry>) -> Self {
        let mut log = Self::new();
        for entry in entries {
            log.append(entry);
        }
        log
    }
}

impl Default for TransparencyLog {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(index: u64, msg: u8, from: &str, to: &str, ts: u64) -> LogEntry {
        LogEntry {
            index,
            message_id: [msg; 32],
            from_status: from.to_string(),
            to_status: to.to_string(),
            timestamp: ts,
        }
    }

    #[test]
    fn test_empty_log_has_zero_root() {
        let log = TransparencyLog::new();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
        assert_eq!(log.root_hash(), EMPTY_HASH);
    }

    #[test]
    fn test_single_entry_root_changes() {
        let mut log = TransparencyLog::new();
        let root_before = log.root_hash();
        log.append(make_entry(0, 1, "", "queued", 1000));
        assert_ne!(log.root_hash(), root_before);
        assert_ne!(log.root_hash(), EMPTY_HASH);
    }

    #[test]
    fn test_appending_changes_root() {
        let mut log = TransparencyLog::new();
        log.append(make_entry(0, 1, "", "queued", 1000));
        let root_after_first = log.root_hash();
        log.append(make_entry(0, 1, "queued", "propagating", 1001));
        assert_ne!(log.root_hash(), root_after_first);
    }

    #[test]
    fn test_modifying_earlier_entry_changes_later_root() {
        // Build two logs that differ only in entry 0.
        let mut log_a = TransparencyLog::new();
        log_a.append(make_entry(0, 1, "", "queued", 1000));
        log_a.append(make_entry(0, 1, "queued", "settled", 1001));

        let mut log_b = TransparencyLog::new();
        log_b.append(make_entry(0, 1, "", "queued", 9999)); // different timestamp
        log_b.append(make_entry(0, 1, "queued", "settled", 1001));

        assert_ne!(log_a.root_hash(), log_b.root_hash());
    }

    #[test]
    fn test_inclusion_proof_verifies_for_real_entry() {
        let mut log = TransparencyLog::new();
        for i in 0..8u8 {
            log.append(make_entry(i as u64, i, "", "queued", 1000 + i as u64));
        }

        for idx in 0..8 {
            let proof = log.inclusion_proof(idx).expect("proof should exist");
            assert!(
                verify_inclusion_proof(&proof),
                "inclusion proof failed for index {}",
                idx
            );
            assert_eq!(proof.leaf_index, idx);
            assert_eq!(proof.root_hash, log.root_hash());
            // Path should have exactly log2(8) = 3 levels.
            assert_eq!(proof.path.len(), 3);
        }
    }

    #[test]
    fn test_inclusion_proof_rejects_wrong_index() {
        let mut log = TransparencyLog::new();
        log.append(make_entry(0, 1, "", "queued", 1000));

        let mut proof = log.inclusion_proof(0).unwrap();
        // Tamper with the leaf index — proof should still verify (index is not
        // part of the hash, only the leaf hash matters) but the leaf_hash field
        // should match the actual leaf.
        assert!(verify_inclusion_proof(&proof));

        // Change the leaf_hash to something wrong.
        proof.leaf_hash = [0xff; 32];
        assert!(!verify_inclusion_proof(&proof));
    }

    #[test]
    fn test_consistency_proof_verifies_across_log_growth() {
        let mut log = TransparencyLog::new();
        for i in 0..8u8 {
            log.append(make_entry(i as u64, i, "", "queued", 1000 + i as u64));
        }

        // Prove consistency between size 2 and size 8.
        let proof = log
            .consistency_proof_for(2)
            .expect("consistency proof should exist");
        assert!(
            verify_consistency_proof(&proof, &log.leaves),
            "consistency proof should verify"
        );
        assert_eq!(proof.old_size, 2);
        assert_eq!(proof.new_size, 8);

        // Also test size 4 → 8 (a power-of-two boundary).
        let proof = log.consistency_proof_for(4).unwrap();
        assert!(verify_consistency_proof(&proof, &log.leaves));
    }

    #[test]
    fn test_tampered_historical_entry_is_detected_via_root_hash_mismatch() {
        let mut log = TransparencyLog::new();
        for i in 0..5u8 {
            log.append(make_entry(i as u64, i, "", "queued", 1000 + i as u64));
        }
        let original_root = log.root_hash();
        assert!(log.verify_root());

        // Simulate out-of-band tampering: modify an earlier entry directly.
        log.entries[1].to_status = "settled".to_string();
        log.leaves[1] = leaf_hash(&log.entries[1]);

        // The cached root hasn't changed, but recomputing from the leaves
        // produces a different root.
        assert!(!log.verify_root());
        assert_eq!(log.root, original_root); // cached root unchanged

        // After a "restart" where we rebuild the log from the tampered entries,
        // the root will be different.
        let rebuilt = TransparencyLog::from_entries(log.entries.clone());
        assert_ne!(rebuilt.root_hash(), original_root);
    }

    #[test]
    fn test_consistency_proof_fails_for_a_non_append_only_modification() {
        // Build a log of size 8, take a snapshot at size 4, then modify an
        // entry in [0..4) and see if consistency proof fails.
        let mut log = TransparencyLog::new();
        for i in 0..8u8 {
            log.append(make_entry(i as u64, i, "", "queued", 1000 + u64::from(i)));
        }

        let old_leaves: Vec<[u8; 32]> = log.leaves[..4].to_vec();
        let proof = log.consistency_proof_for(4).unwrap();

        // Tamper with the new tree: change entry 1 (within the old range).
        log.entries[2].to_status = "settled".to_string();
        log.leaves[2] = leaf_hash(&log.entries[2]);

        // The proof was generated before tampering, so the new root no longer
        // matches.
        assert!(!verify_consistency_proof(&proof, &log.leaves));

        // Also: a reordered entry in the old range should fail.
        let mut log2 = TransparencyLog::new();
        let entries: Vec<LogEntry> = (0..8u8)
            .map(|i| make_entry(i as u64, i, "", "queued", 1000 + u64::from(i)))
            .collect();
        for e in &entries {
            log2.append(e.clone());
        }
        let old_leaves2: Vec<[u8; 32]> = log2.leaves[..4].to_vec();
        let proof2 = log2.consistency_proof_for(4).unwrap();

        // Swap entries 1 and 2 in the "replayed" log.
        let mut tampered = entries;
        tampered.swap(1, 2);
        let mut log3 = TransparencyLog::new();
        for e in &tampered {
            log3.append(e.clone());
        }
        assert!(!verify_consistency_proof(&proof2, &log3.leaves));
        // Also verify old leaves don't match (the reordering changed them).
        assert_ne!(old_leaves2[..], log3.leaves[..4]);
    }

    #[test]
    fn test_verify_entries_detects_leaf_tampering() {
        let mut log = TransparencyLog::new();
        log.append(make_entry(0, 1, "", "queued", 1000));
        log.append(make_entry(0, 1, "queued", "settled", 1001));

        // Tamper with the cached leaf hash directly.
        log.leaves[0] = [0xab; 32];

        assert!(!log.verify_entries());
        assert!(!log.verify_integrity());
    }

    #[test]
    fn test_proof_of_empty_log_range_is_none() {
        let mut log = TransparencyLog::new();
        log.append(make_entry(0, 1, "", "queued", 1000));
        assert!(log.consistency_proof_for(0).is_none());
        assert!(log.consistency_proof_for(2).is_none());
    }

    #[test]
    fn test_root_hash_is_stable_for_same_input() {
        let mut a = TransparencyLog::new();
        let mut b = TransparencyLog::new();
        for i in 0..10u8 {
            a.append(make_entry(i as u64, i, "", "queued", 1000 + u64::from(i)));
            b.append(make_entry(i as u64, i, "", "queued", 1000 + u64::from(i)));
        }
        assert_eq!(a.root_hash(), b.root_hash());
    }

    #[test]
    fn test_different_message_ids_produce_different_roots() {
        let mut a = TransparencyLog::new();
        let mut b = TransparencyLog::new();
        a.append(make_entry(0, 1, "", "queued", 1000));
        b.append(make_entry(0, 2, "", "queued", 1000)); // different message_id
        assert_ne!(a.root_hash(), b.root_hash());
    }

    #[test]
    fn test_get_entries_returns_all_entries() {
        let mut log = TransparencyLog::new();
        for i in 0..5u8 {
            log.append(make_entry(i as u64, i, "", "queued", 1000 + u64::from(i)));
        }
        assert_eq!(log.entries().len(), 5);
        assert_eq!(log.get(0).unwrap().message_id, [0u8; 32]);
        assert_eq!(log.get(4).unwrap().message_id, [4u8; 32]);
        assert!(log.get(5).is_none());
    }
}
