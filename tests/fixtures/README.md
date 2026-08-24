# Test fixtures: Stellar transaction envelope XDR

Each `*.b64` file is a single base64-encoded Stellar `TransactionEnvelope`,
generated with the [`stellar-xdr`](https://crates.io/crates/stellar-xdr) crate
(the same `22.1` release this crate depends on). They exercise
`stellarconduit_sync_engine::envelope::xdr::extract_source_account_and_sequence`
and the XDR cross-check in `OfflineEnvelopeBuilder::build_and_sign`.

All fixtures share these deterministic values, derived from fixed ed25519 keys
(`0x11`, `0x22`, `0x33` repeated 32 times):

| Field           | Value                                                      |
| --------------- | ---------------------------------------------------------- |
| Source account  | `GAIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCF6M`  |
| Destination     | `GARCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCFRVX`  |
| Fee source      | `GAZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTHCM6`  |
| Sequence number | `103720918407610369`                                       |

| File                                    | Description                                                                                   |
| --------------------------------------- | --------------------------------------------------------------------------------------------- |
| `transaction_v1_envelope.b64`           | Canonical `TransactionV1Envelope`: one native payment, text memo, one placeholder signature.  |
| `transaction_v1_envelope_seq_next.b64`  | Same source, sequence + 1 (for successive-build tests).                                        |
| `transaction_v1_envelope_conflict.b64`  | Same source and sequence, different payment amount — a genuine double-spend counterpart.       |
| `transaction_v1_envelope_muxed.b64`     | Muxed (`M...`) source over the same base account; must collapse onto the base `G...` account.  |
| `fee_bump_envelope.b64`                 | `FeeBumpTransactionEnvelope` wrapping the canonical V1; fee paid by the fee source.            |

The signatures in these fixtures are placeholders (not valid Ed25519
signatures): the XDR parser reads the envelope structure and does not verify
signatures. To regenerate, see the generator described in the pull request.
