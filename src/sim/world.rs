//! Multi-device simulated mesh state the agents act on.
//!
//! This is not a reimplementation of the sync engine — it holds the
//! [`QueuedSlot`]s / [`RelayObservation`]s that real
//! [`crate::conflict`] APIs consume, partitioned by simulated device so
//! race agents can model split views that later merge.

use std::collections::BTreeMap;

use crate::conflict::{ConflictEvidence, QueuedSlot, RelayObservation};

/// One simulated peer / relay terminal.
#[derive(Debug, Clone, Default)]
pub struct SimDevice {
    pub id: String,
    /// Local view of queued (account, sequence, message_id) slots.
    pub slots: Vec<QueuedSlot>,
    /// Observations this device has collected, keyed by message_id hex.
    pub observations: BTreeMap<String, Vec<RelayObservation>>,
}

/// Shared conceptual state across devices for one harness run.
#[derive(Debug, Clone, Default)]
pub struct SimWorld {
    pub devices: BTreeMap<String, SimDevice>,
    /// Account used by race / replay scenarios unless overridden.
    pub account: String,
    /// Contested sequence number for the default scenario.
    pub sequence: i64,
    /// Wall-clock (simulated) after which observations are considered stale.
    pub observation_ttl_secs: u64,
    /// When each observation batch was first accepted, by message_id hex.
    pub observation_accepted_at: BTreeMap<String, u64>,
}

impl SimWorld {
    pub fn new(account: impl Into<String>, sequence: i64) -> Self {
        Self {
            devices: BTreeMap::new(),
            account: account.into(),
            sequence,
            observation_ttl_secs: 60,
            observation_accepted_at: BTreeMap::new(),
        }
    }

    pub fn ensure_device(&mut self, id: &str) -> &mut SimDevice {
        self.devices
            .entry(id.to_string())
            .or_insert_with(|| SimDevice {
                id: id.to_string(),
                ..SimDevice::default()
            })
    }

    /// Union of every device's slots (deduped by message_id, stable order).
    pub fn merged_slots(&self) -> Vec<QueuedSlot> {
        let mut by_id: BTreeMap<[u8; 32], QueuedSlot> = BTreeMap::new();
        for device in self.devices.values() {
            for slot in &device.slots {
                by_id.entry(slot.message_id).or_insert_with(|| slot.clone());
            }
        }
        by_id.into_values().collect()
    }

    pub fn observations_for(&self, message_id: &[u8; 32]) -> Vec<RelayObservation> {
        let key = hex::encode(message_id);
        let mut out = Vec::new();
        for device in self.devices.values() {
            if let Some(obs) = device.observations.get(&key) {
                out.extend(obs.iter().cloned());
            }
        }
        out
    }

    pub fn evidence_for_pair(
        &self,
        envelope_a: &[u8; 32],
        envelope_b: &[u8; 32],
        ts_a: u64,
        ts_b: u64,
    ) -> ConflictEvidence {
        ConflictEvidence {
            envelope_a_timestamp: ts_a,
            envelope_b_timestamp: ts_b,
            envelope_a_observations: self.observations_for(envelope_a),
            envelope_b_observations: self.observations_for(envelope_b),
        }
    }
}
