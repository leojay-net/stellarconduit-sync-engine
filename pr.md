# Database Export/Import for Device Migration

Addresses #15.

## Problem

There was no way to move a `SyncEngineDb`'s state — pending payments, sequence reservations, unresolved conflicts, dispute escalations, settlement history — from one device to another. For the population StellarConduit targets (disaster-relief/displacement scenarios), losing that state because a phone was lost, broken, or replaced means losing pending offline payments that may represent emergency funds.

## What's here

Two new methods on `SyncEngineDb` (`src/storage/db.rs`):

- `export_snapshot(&self) -> Result<Vec<u8>, SyncEngineError>` — serializes every table into a single versioned MessagePack blob.
- `import_snapshot(&self, data: &[u8]) -> Result<ImportReport, SyncEngineError>` — restores a blob produced by `export_snapshot` into this database.

Snapshot rows mirror table columns directly (rather than going through the domain types used elsewhere in this file, e.g. `Conflict`/`DisputeEscalation`), so the round-trip is byte-exact instead of passing through a second encode/decode step that could silently normalize or lose data.

## Versioning (issue #11)

Issue #11 (schema versioning/migrations for `SyncEngineDb`) hadn't landed at the time this was picked up, so this adds its own minimal, standalone tag — `DB_SNAPSHOT_SCHEMA_VERSION` — scoped only to the snapshot format, rather than inventing a general migration scheme. `import_snapshot` rejects any blob whose embedded version doesn't match, via a new `SyncEngineError::IncompatibleSnapshotSchemaVersion`. If #11 lands later, this constant should be unified with its scheme, not kept as a second, competing version number.

## Import policy: reject into a non-empty database

`import_snapshot` **rejects the import** (`SyncEngineError::ImportTargetNotEmpty`) if the target database already contains any rows, in any table. It does not merge or overwrite.

This was a deliberate choice over merge/overwrite: every table here guards financial or double-spend-sensitive state. Silently merging two `sequence_reservations` rows for the same account, or two `conflicts`/`queued_envelopes` rows, would need a conflict-resolution policy no less complex than the one `crate::conflict` already exists to implement for on-chain envelopes — inventing a second, weaker one just for import risks the exact double-spend and lost-payment hazards this crate is otherwise built to prevent. Reject-if-nonempty keeps the outcome trivially provable (`empty + snapshot = snapshot`, exactly) and matches the issue's intended use case: restoring onto a new device, whose database is normally fresh.

The emptiness check and the row inserts happen inside a single SQLite transaction, so a concurrent writer landing between "check" and "insert" can't produce a partial or corrupt import — `SyncEngineDb` is designed to be shared behind an `Arc` across concurrent callers, so this isn't a hypothetical.

## Interaction with encryption at rest (issue #12)

Issue #12 hadn't landed either, so this format has no encryption of its own — `export_snapshot` reads and serializes whatever plaintext rows the connection can see. This is documented explicitly on both functions: **an exported snapshot is not an encrypted artifact merely because the source database is encrypted at rest.** Encryption at rest protects the on-disk SQLite file, not the output of `export_snapshot`. A snapshot is exactly as sensitive as the payment history it contains (source accounts, sequence numbers, full transaction envelopes, dispute proofs) and callers must treat it as plaintext financial data: transmit only over an encrypted channel, don't persist it unencrypted at rest, and ideally wrap it in caller-side encryption (using the same key material as #12's at-rest encryption, so a snapshot is never a plaintext copy of something the source database was encrypting) before writing it anywhere.

## Interaction with stale sequence reservations (issue #8)

`sequence_reservations` rows are exported and imported as-is. A sequence baseline reserved on the source device may be stale by the time it reaches the target device (e.g. the account transacted from elsewhere in the interim). This is documented as a required post-import step, not implemented here: **callers must run stale-sequence reconciliation (#8) immediately after `import_snapshot` returns and before queuing anything new** — this function has no live network access to the account and can't validate the reservation itself.

## Corrupted / truncated input

A `data` blob that isn't a valid, complete snapshot encoding fails with `SyncEngineError::DeserializationError` before anything is written — there's no partial-write state to reason about, and no panic path.

## Testing

Required tests, all in `src/storage/db.rs`:
- `test_export_import_roundtrip_is_lossless` — seeds every table, exports, imports into a fresh database, and asserts every table matches exactly (including `DbSummary`, ordered comparisons for envelopes/conflicts/escalations/history/reservations).
- `test_import_into_nonempty_db_follows_documented_policy` — importing into a database with existing rows returns `ImportTargetNotEmpty`, and neither the target's pre-existing rows nor the snapshot's rows are mutated.
- `test_import_rejects_corrupted_snapshot` — both garbage bytes and a truncated real snapshot fail with `DeserializationError`, and nothing is written either time.
- `test_import_rejects_incompatible_schema_version` — a snapshot tagged with `DB_SNAPSHOT_SCHEMA_VERSION + 1` is rejected with `IncompatibleSnapshotSchemaVersion` before any table is touched.

```
cargo fmt --all -- --check                          # clean
cargo clippy --all-targets -- -D warnings           # clean
cargo test                                           # 172 unit + 13 integration passed, 0 failed
```

Note: this repo's pinned `stellarconduit-core` git dependency fails to build natively on macOS (`mdns-sd` is gated to `cfg(target_os = "linux")` in its `Cargo.toml`, but two of its modules use it unconditionally with no matching `#[cfg]`). This is pre-existing on `main` and unrelated to this change — verified via a temporary local-only patch to the cached dependency checkout (reverted afterward, nothing in this repo touched) since CI runs on `ubuntu-latest` where it's a non-issue.

## Commits

1. `errors: add error variants for snapshot export/import`
2. `storage: implement snapshot export/import for device migration`
3. `storage: add required tests for snapshot export/import`
