# Local Diagnostic CLI for Inspecting Sync Engine Database State

Closes #62.

## Summary

Adds `sync-engine-cli`, a read-only diagnostic binary for pointing at a device's `SyncEngineDb` SQLite file and getting readable answers to "what's currently queued," "what's this account's settlement history," and "are there unresolved conflicts" — without writing a throwaway script or attaching a debugger.

```bash
cargo build --bin sync-engine-cli

sync-engine-cli --db-path wallet.sqlite3 queue list --account GABC... --priority emergency
sync-engine-cli --db-path wallet.sqlite3 settlement status <message_id_hex>
sync-engine-cli --db-path wallet.sqlite3 conflicts list --unresolved-only
sync-engine-cli --db-path wallet.sqlite3 db summary
sync-engine-cli --db-path wallet.sqlite3 --json queue list   # machine-readable
```

## What's included

- **`queue list [--account] [--priority]`** — queued envelopes, sorted oldest-first, optionally filtered by source account and/or priority tier.
- **`settlement status <message_id>`** — current status plus full transition history for one envelope (hex-encoded message id).
- **`conflicts list [--unresolved-only]`** — recorded double-spend conflicts, optionally filtered to unresolved ones.
- **`db summary`** — row counts per table plus the oldest/newest queued entry.
- **`--json`** — machine-readable output for every subcommand, built from the exact same data-assembly functions as the table output, so the two can't drift apart.

## Design notes

- **Thin binary, fat library.** `src/bin/sync-engine-cli.rs` is ~20 lines; all argument parsing, data assembly, and rendering lives in `src/cli.rs`. This is what lets the integration tests exercise the CLI's actual logic directly against a real `SyncEngineDb`, since a test crate can depend on this crate's library target but not on its `[[bin]]`.
- **Read-only, with two narrowly-scoped exceptions.** The CLI only reads. `SyncEngineDb` gained two small additive accessors it didn't already expose, both read-only:
  - `list_all_conflicts()` — every recorded conflict (resolved and unresolved) with `id`/`detected_at`/`resolved`, since the existing `list_unresolved_conflicts()` only returns unresolved rows and drops those fields.
  - `summary()` — row counts per table plus oldest/newest `queued_envelopes.enqueued_at`, via plain `COUNT`/`MIN`/`MAX` queries. Nothing already on `SyncEngineDb` aggregates across tables.

  Neither changes any existing method's signature or behavior.
- **`clap` moved from `[dev-dependencies]` to `[dependencies]`.** It was already present as a dev-dependency (used by `examples/mock_relay.rs`), but dev-dependencies aren't linked for a crate's own `[[bin]]` targets under a normal `cargo build` — only for `cargo test`/`--examples`/`--benches`. `sync-engine-cli` needed it at normal build time.

## Testing

Four integration tests in `tests/integration/cli_test.rs`, built the same way this crate's other integration tests are (see `queue_storage_roundtrip_test.rs`), against real `SyncEngineDb` instances:

- `test_queue_list_reflects_actual_db_state` — enqueues several envelopes and checks ordering plus account/priority filters (individually and combined).
- `test_settlement_status_lookup_for_known_message_id` — full transition history for a tracked id, plus an untracked id (valid, non-error, empty result) and malformed hex (rejected as `CliError::InvalidMessageId`, not a panic).
- `test_conflicts_list_unresolved_only_filter` — records two conflicts, marks one resolved via a raw `rusqlite` connection to the same file (there's no public writer for that column yet — see the note in the test), and confirms the filter excludes it.
- `test_json_output_is_valid_and_complete` — parses `--json` output for `queue list` and `db summary` and checks every field against the plain (non-JSON) data-assembly result, field-for-field.

Also manually smoke-tested the built binary end-to-end against a populated SQLite file: all four subcommands, `--json` on each, and the invalid-hex error path.

```
cargo fmt --all -- --check         # clean
cargo clippy --all-targets --all-features -- -D warnings   # clean
cargo test                          # 173 passed (including the 4 above), 0 failed
```

## Commits

1. `build: move clap to dependencies, add serde_json`
2. `feat(storage): add read-only conflict/summary accessors to SyncEngineDb`
3. `feat(cli): scaffold sync-engine-cli argument parsing`
4. `feat(cli): add data-assembly layer for sync-engine-cli`
5. `feat(cli): add rendering and dispatch for sync-engine-cli`
6. `feat(bin): add sync-engine-cli binary`
7. `test(cli): add integration tests for sync-engine-cli`
8. `docs(readme): document sync-engine-cli usage`
