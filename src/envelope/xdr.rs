//! Deriving the *true* source account and sequence number from an
//! already-built Stellar transaction envelope XDR.
//!
//! Elsewhere in this crate `tx_xdr` is treated as an opaque, base64-encoded
//! blob (see [`crate::envelope::builder`]). That opacity is a liability for
//! conflict detection: the source account and sequence number a caller *claims*
//! for an envelope are what [`crate::conflict::detector`] groups on, but nothing
//! forced those claims to agree with the transaction that actually got signed.
//! A buggy or compromised caller could label two genuinely conflicting
//! envelopes as belonging to different accounts or sequences, and the
//! double-spend this whole module exists to catch would slip through.
//!
//! The real source account and sequence number are encoded inside the
//! transaction XDR itself. This module parses them back out so callers can be
//! held to what they actually signed rather than trusted at their word.
//!
//! ## XDR dependency
//!
//! Parsing uses the official [`stellar_xdr`] crate, pinned to the same `22.1`
//! release that already reaches this crate transitively through
//! `stellarconduit-core -> soroban-sdk`. Depending on it directly (rather than
//! reaching through `soroban-sdk`'s re-export) keeps the mobile-wallet
//! dependency footprint flat — no new crate versions enter the graph — while
//! exposing exactly the transaction types we need and none of the Soroban host
//! machinery. See the `Cargo.toml` dependency note for details.

use stellar_xdr::curr::{
    FeeBumpTransactionInnerTx, Limits, MuxedAccount, PublicKey, ReadXdr, SequenceNumber,
    TransactionEnvelope, Uint256, WriteXdr,
};

use crate::errors::SyncEngineError;

/// Base64-decode and parse `tx_xdr` as a Stellar [`TransactionEnvelope`],
/// returning the `(source_account, sequence)` pair actually encoded inside it.
///
/// The source account is returned as a `G...` StrKey string. For a fee-bump
/// transaction, the *inner* transaction's source and sequence are returned:
/// the fee-bump only changes who pays the fee, while the sequence number is
/// still consumed on the inner transaction's source account — that is the slot
/// conflict detection must key on. For a muxed (`M...`) source, the underlying
/// base account is returned, since the sequence number lives on the base
/// account regardless of the muxing.
///
/// # Errors
///
/// Returns [`SyncEngineError::XdrParse`] if `tx_xdr` is not valid base64 or does
/// not decode to a well-formed transaction envelope. Malformed or truncated
/// input never panics.
pub fn extract_source_account_and_sequence(tx_xdr: &str) -> Result<(String, i64), SyncEngineError> {
    let envelope = TransactionEnvelope::from_xdr_base64(tx_xdr, Limits::none())
        .map_err(|e| SyncEngineError::XdrParse(e.to_string()))?;

    let (account, sequence) = match envelope {
        TransactionEnvelope::Tx(env) => (
            muxed_source_strkey(&env.tx.source_account),
            env.tx.seq_num.0,
        ),
        TransactionEnvelope::TxFeeBump(env) => {
            // The only inner-transaction variant a fee-bump can wrap is a V1
            // transaction; its source account owns the sequence number.
            let FeeBumpTransactionInnerTx::Tx(inner) = env.tx.inner_tx;
            (
                muxed_source_strkey(&inner.tx.source_account),
                inner.tx.seq_num.0,
            )
        }
        TransactionEnvelope::TxV0(env) => {
            // V0 predates muxed accounts: the source is a bare ed25519 key.
            (
                ed25519_to_strkey(&env.tx.source_account_ed25519),
                env.tx.seq_num.0,
            )
        }
    };

    Ok((account, sequence))
}

/// Parses an existing transaction envelope XDR, updates its sequence number to
/// `new_sequence`, and returns the re-serialized XDR base64 string.
///
/// If the transaction is a fee-bump transaction, the inner transaction's sequence
/// number is updated.
pub fn with_updated_sequence(tx_xdr: &str, new_sequence: i64) -> Result<String, SyncEngineError> {
    let mut envelope = TransactionEnvelope::from_xdr_base64(tx_xdr, Limits::none())
        .map_err(|e| SyncEngineError::XdrParse(e.to_string()))?;

    match &mut envelope {
        TransactionEnvelope::Tx(env) => {
            env.tx.seq_num = SequenceNumber(new_sequence);
        }
        TransactionEnvelope::TxFeeBump(env) => {
            let FeeBumpTransactionInnerTx::Tx(inner) = &mut env.tx.inner_tx;
            inner.tx.seq_num = SequenceNumber(new_sequence);
        }
        TransactionEnvelope::TxV0(env) => {
            env.tx.seq_num = SequenceNumber(new_sequence);
        }
    }

    envelope
        .to_xdr_base64(Limits::none())
        .map_err(|e| SyncEngineError::XdrParse(e.to_string()))
}

/// Reduce a (possibly muxed) source account to the `G...` StrKey of its base
/// ed25519 account.
fn muxed_source_strkey(account: &MuxedAccount) -> String {
    let key = match account {
        MuxedAccount::Ed25519(key) => key,
        MuxedAccount::MuxedEd25519(muxed) => &muxed.ed25519,
    };
    ed25519_to_strkey(key)
}

/// Encode a 32-byte ed25519 public key as a `G...` StrKey string.
///
/// A `Uint256` is always exactly 32 bytes, so the StrKey encoding cannot fail.
fn ed25519_to_strkey(key: &Uint256) -> String {
    PublicKey::PublicKeyTypeEd25519(key.clone()).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fixtures are real, valid XDR generated with the `stellar-xdr` crate; see
    // the PR description / `tests/fixtures` for the generator. All share these
    // deterministic values.
    const SOURCE_G: &str = "GAIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCF6M";
    const FEE_SOURCE_G: &str = "GAZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTHCM6";
    const SEQ: i64 = 103_720_918_407_610_369;

    fn fixture(name: &str) -> String {
        let path = format!("{}/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name);
        std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("failed to read fixture {name}: {e}"))
            .trim()
            .to_string()
    }

    #[test]
    fn test_extract_account_and_sequence_from_valid_xdr() {
        let xdr = fixture("transaction_v1_envelope.b64");
        let (account, sequence) = extract_source_account_and_sequence(&xdr).unwrap();
        assert_eq!(account, SOURCE_G);
        assert_eq!(sequence, SEQ);
    }

    #[test]
    fn test_extract_from_muxed_source_yields_base_account() {
        // A muxed (M...) source must collapse onto the same base G-account, so
        // that conflict detection keys the sequence on the right account.
        let xdr = fixture("transaction_v1_envelope_muxed.b64");
        let (account, sequence) = extract_source_account_and_sequence(&xdr).unwrap();
        assert_eq!(account, SOURCE_G);
        assert_eq!(sequence, SEQ);
    }

    #[test]
    fn test_extract_from_fee_bump_uses_inner_transaction() {
        // The fee source differs from the inner source; the sequence is
        // consumed on the inner transaction's source, which is what we return.
        let xdr = fixture("fee_bump_envelope.b64");
        let (account, sequence) = extract_source_account_and_sequence(&xdr).unwrap();
        assert_eq!(account, SOURCE_G);
        assert_ne!(account, FEE_SOURCE_G);
        assert_eq!(sequence, SEQ);
    }

    #[test]
    fn test_extract_rejects_malformed_base64() {
        // '!' is not a base64 character.
        let result = extract_source_account_and_sequence("not valid base64 !!!");
        assert!(matches!(result, Err(SyncEngineError::XdrParse(_))));
    }

    #[test]
    fn test_extract_rejects_truncated_xdr() {
        // Valid base64 of a truncated envelope: decodes to bytes, but the XDR
        // structure is incomplete.
        let full = fixture("transaction_v1_envelope.b64");
        let truncated = &full[..full.len() / 2];
        let result = extract_source_account_and_sequence(truncated);
        assert!(matches!(result, Err(SyncEngineError::XdrParse(_))));
    }

    #[test]
    fn test_extract_rejects_empty_input() {
        let result = extract_source_account_and_sequence("");
        assert!(matches!(result, Err(SyncEngineError::XdrParse(_))));
    }
}
