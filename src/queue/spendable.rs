//! Spendable-balance estimation for locally queued envelopes.
//!
//! The envelope's `tx_xdr` is intentionally opaque at this layer. Until the
//! transaction-operation parser is extended to derive payment amounts, the
//! caller must provide the amount associated with each queued envelope.

use crate::settlement::SettlementStatus;
use crate::storage::QueuedEnvelopeRecord;

/// A queued envelope plus the caller-supplied payment amount and its current
/// settlement status.
///
/// `amount` is expressed in the account's balance asset's smallest unit and
/// must be non-negative. It is interim metadata: the current XDR parser
/// derives source accounts and sequence numbers, but does not yet derive
/// payment operations or asset amounts from opaque transaction XDR.
#[derive(Debug, Clone, PartialEq)]
pub struct QueuedEnvelopeSpend {
    pub record: QueuedEnvelopeRecord,
    pub amount: i64,
    pub status: SettlementStatus,
}

impl QueuedEnvelopeSpend {
    /// Combine a queued record with its caller-supplied amount and status.
    pub fn new(record: QueuedEnvelopeRecord, amount: i64, status: SettlementStatus) -> Self {
        Self {
            record,
            amount,
            status,
        }
    }
}

/// Estimate how much of an account's last-known balance remains spendable.
///
/// `known_balance` is the most recent on-chain balance observed by the caller,
/// not a live network balance. Every matching envelope in `queued` whose
/// status is `Queued`, `Propagating`, or `Disputed` is treated as a reservation;
/// `Settled` and `Failed` envelopes are excluded. A disputed envelope remains
/// reserved until its dispute reaches a terminal outcome because it may still
/// settle and its funds therefore remain committed. This conservative policy
/// favors preventing a predictable double-spend over temporarily understating
/// available funds.
///
/// The result is an estimate, not a guarantee: the known balance may be stale,
/// and caller-supplied amounts must accurately describe the queued payments.
/// Negative amounts are ignored, and arithmetic saturates to avoid overflow.
pub fn estimate_spendable(
    account: &str,
    known_balance: i64,
    queued: &[QueuedEnvelopeSpend],
) -> i64 {
    let reserved = queued
        .iter()
        .filter(|spend| {
            spend.record.source_account == account
                && matches!(
                    spend.status,
                    SettlementStatus::Queued
                        | SettlementStatus::Propagating
                        | SettlementStatus::Disputed
                )
                && spend.amount >= 0
        })
        .fold(0_i64, |total, spend| total.saturating_add(spend.amount));

    known_balance.saturating_sub(reserved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellarconduit_core::message::types::TransactionEnvelope;

    fn spend(account: &str, id: u8, amount: i64, status: SettlementStatus) -> QueuedEnvelopeSpend {
        QueuedEnvelopeSpend::new(
            QueuedEnvelopeRecord {
                envelope: TransactionEnvelope {
                    message_id: [id; 32],
                    origin_pubkey: [0; 32],
                    tx_xdr: String::new(),
                    ttl_hops: 0,
                    timestamp: 0,
                    signature: [0; 64],
                },
                source_account: account.to_string(),
                sequence: i64::from(id),
                priority: TxPriority::Normal,
                enqueued_at: 0,
            },
            amount,
            status,
        )
    }
    use crate::queue::TxPriority;

    #[test]
    fn test_spendable_excludes_settled_and_failed() {
        let queued = [
            spend("G-account", 1, 30, SettlementStatus::Settled),
            spend("G-account", 2, 20, SettlementStatus::Failed),
            spend("other", 3, 100, SettlementStatus::Queued),
        ];

        assert_eq!(estimate_spendable("G-account", 100, &queued), 100);
    }

    #[test]
    fn test_spendable_includes_queued_and_propagating() {
        let queued = [
            spend("G-account", 1, 30, SettlementStatus::Queued),
            spend("G-account", 2, 20, SettlementStatus::Propagating),
        ];

        assert_eq!(estimate_spendable("G-account", 100, &queued), 50);
    }

    #[test]
    fn test_spendable_disputed_handling_matches_documented_policy() {
        let queued = [spend("G-account", 1, 40, SettlementStatus::Disputed)];

        assert_eq!(estimate_spendable("G-account", 100, &queued), 60);
    }

    #[test]
    fn test_multiple_queued_envelopes_for_same_account_sum_correctly() {
        let queued = [
            spend("G-account", 1, 25, SettlementStatus::Queued),
            spend("G-account", 2, 35, SettlementStatus::Propagating),
            spend("G-account", 3, 15, SettlementStatus::Disputed),
        ];

        assert_eq!(estimate_spendable("G-account", 100, &queued), 25);
    }
}
