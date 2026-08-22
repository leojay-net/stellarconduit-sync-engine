//! Integration tests for `sync-engine-cli`'s library backing (`src/cli.rs`).
//!
//! These drive the same data-assembly functions the binary calls, against a
//! `SyncEngineDb` built the way this crate's other integration tests build
//! one (see `queue_storage_roundtrip_test.rs`), so they exercise real
//! read paths against a populated database rather than mocks.

use stellarconduit_core::message::types::TransactionEnvelope;
use stellarconduit_sync_engine::cli::{
    conflicts_list, db_summary, dispatch, queue_list, settlement_status, CliError, Command,
    DbAction, QueueAction,
};
use stellarconduit_sync_engine::conflict::Conflict;
use stellarconduit_sync_engine::queue::TxPriority;
use stellarconduit_sync_engine::settlement::SettlementStatus;
use stellarconduit_sync_engine::storage::SyncEngineDb;

/// Same shape used by this crate's other unit/integration tests (e.g.
/// `src/storage/db.rs`'s `mock_envelope`) -- a minimal, syntactically valid
/// `TransactionEnvelope` that doesn't require a full XDR-signing ceremony,
/// since the CLI's read paths only care about what's already durably stored.
fn mock_envelope(message_id: u8) -> TransactionEnvelope {
    TransactionEnvelope {
        message_id: [message_id; 32],
        origin_pubkey: [1u8; 32],
        tx_xdr: "mock_xdr".to_string(),
        ttl_hops: 10,
        timestamp: 1_700_000_000,
        signature: [0u8; 64],
    }
}

#[tokio::test]
async fn test_queue_list_reflects_actual_db_state() {
    let db = SyncEngineDb::init(":memory:").await.unwrap();

    db.enqueue_envelope(&mock_envelope(1), "GAAAA", 101, TxPriority::Low, 1_000)
        .await
        .unwrap();
    db.enqueue_envelope(
        &mock_envelope(2),
        "GBBBB",
        202,
        TxPriority::Emergency,
        2_000,
    )
    .await
    .unwrap();
    db.enqueue_envelope(&mock_envelope(3), "GAAAA", 102, TxPriority::Normal, 3_000)
        .await
        .unwrap();

    // No filters: every queued envelope, oldest first.
    let all = queue_list(&db, None, None).await.unwrap();
    assert_eq!(all.len(), 3);
    assert_eq!(all[0].message_id, hex::encode([1u8; 32]));
    assert_eq!(all[0].source_account, "GAAAA");
    assert_eq!(all[0].sequence, 101);
    assert_eq!(all[0].priority, "low");
    assert_eq!(all[0].enqueued_at, 1_000);
    assert_eq!(all[1].message_id, hex::encode([2u8; 32]));
    assert_eq!(all[2].message_id, hex::encode([3u8; 32]));

    // Filtered by account: only GAAAA's two entries, in enqueue order.
    let by_account = queue_list(&db, Some("GAAAA"), None).await.unwrap();
    assert_eq!(by_account.len(), 2);
    assert!(by_account.iter().all(|r| r.source_account == "GAAAA"));
    assert_eq!(by_account[0].sequence, 101);
    assert_eq!(by_account[1].sequence, 102);

    // Filtered by priority: only the Emergency entry.
    let by_priority = queue_list(&db, None, Some(TxPriority::Emergency))
        .await
        .unwrap();
    assert_eq!(by_priority.len(), 1);
    assert_eq!(by_priority[0].message_id, hex::encode([2u8; 32]));

    // Filters combine (AND).
    let by_both = queue_list(&db, Some("GBBBB"), Some(TxPriority::Emergency))
        .await
        .unwrap();
    assert_eq!(by_both.len(), 1);
    let none_match = queue_list(&db, Some("GAAAA"), Some(TxPriority::Emergency))
        .await
        .unwrap();
    assert!(none_match.is_empty());
}

#[tokio::test]
async fn test_settlement_status_lookup_for_known_message_id() {
    let db = SyncEngineDb::init(":memory:").await.unwrap();
    let message_id = [7u8; 32];

    db.set_settlement_status(message_id, SettlementStatus::Queued, 1_000)
        .await
        .unwrap();
    db.set_settlement_status(message_id, SettlementStatus::Propagating, 1_100)
        .await
        .unwrap();
    db.set_settlement_status(message_id, SettlementStatus::Settled, 1_200)
        .await
        .unwrap();

    let view = settlement_status(&db, &hex::encode(message_id))
        .await
        .unwrap();

    assert_eq!(view.message_id, hex::encode(message_id));
    assert_eq!(view.current_status.as_deref(), Some("settled"));
    assert_eq!(view.history.len(), 3);
    assert_eq!(view.history[0].from_status, "");
    assert_eq!(view.history[0].to_status, "queued");
    assert_eq!(view.history[0].timestamp, 1_000);
    assert_eq!(view.history[1].from_status, "queued");
    assert_eq!(view.history[1].to_status, "propagating");
    assert_eq!(view.history[2].from_status, "propagating");
    assert_eq!(view.history[2].to_status, "settled");

    // An id never tracked is a valid, non-error lookup with no status/history.
    let untracked = settlement_status(&db, &hex::encode([9u8; 32]))
        .await
        .unwrap();
    assert_eq!(untracked.current_status, None);
    assert!(untracked.history.is_empty());

    // Malformed hex is rejected with a CLI-level error, not a panic.
    let err = settlement_status(&db, "not-hex").await.unwrap_err();
    assert!(matches!(err, CliError::InvalidMessageId(_)));
}

#[tokio::test]
async fn test_conflicts_list_unresolved_only_filter() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("cli-conflicts-test.sqlite3");
    let path_str = path.to_string_lossy().into_owned();

    let db = SyncEngineDb::init(&path_str).await.unwrap();
    let conflict_a = Conflict {
        source_account: "GAAAA".to_string(),
        sequence: 1,
        envelope_a: [1u8; 32],
        envelope_b: [2u8; 32],
    };
    let conflict_b = Conflict {
        source_account: "GBBBB".to_string(),
        sequence: 2,
        envelope_a: [3u8; 32],
        envelope_b: [4u8; 32],
    };
    db.record_conflict(&conflict_a, 1_000).await.unwrap();
    db.record_conflict(&conflict_b, 2_000).await.unwrap();

    // Mark the first conflict resolved via a raw connection to the same
    // file -- there is no public writer for this on `SyncEngineDb` yet (see
    // `src/conflict/resolver.rs`'s `UnresolvedConflict` path, which is the
    // only place a resolution outcome is decided today, and doesn't persist
    // it). This simulates what a future on-chain-arbitration writer would
    // do, without adding a write accessor the read-only CLI itself has no
    // use for.
    {
        let raw = rusqlite::Connection::open(&path_str).unwrap();
        raw.execute("UPDATE conflicts SET resolved = 1 WHERE sequence = 1", [])
            .unwrap();
    }

    let all = conflicts_list(&db, false).await.unwrap();
    assert_eq!(all.len(), 2);
    assert!(all.iter().any(|c| c.sequence == 1 && c.resolved));
    assert!(all.iter().any(|c| c.sequence == 2 && !c.resolved));

    let unresolved = conflicts_list(&db, true).await.unwrap();
    assert_eq!(unresolved.len(), 1);
    assert_eq!(unresolved[0].sequence, 2);
    assert_eq!(unresolved[0].source_account, "GBBBB");
    assert!(!unresolved[0].resolved);
}

#[tokio::test]
async fn test_json_output_is_valid_and_complete() {
    let db = SyncEngineDb::init(":memory:").await.unwrap();

    db.enqueue_envelope(
        &mock_envelope(1),
        "GAAAA",
        101,
        TxPriority::Emergency,
        1_000,
    )
    .await
    .unwrap();
    db.set_settlement_status([1u8; 32], SettlementStatus::Queued, 1_000)
        .await
        .unwrap();
    let conflict = Conflict {
        source_account: "GAAAA".to_string(),
        sequence: 101,
        envelope_a: [1u8; 32],
        envelope_b: [5u8; 32],
    };
    db.record_conflict(&conflict, 1_500).await.unwrap();

    // `queue list --json` is valid JSON containing the same rows/fields as
    // the plain data-assembly function.
    let expected_rows = queue_list(&db, None, None).await.unwrap();
    let json_output = dispatch(
        &db,
        &Command::Queue {
            action: QueueAction::List {
                account: None,
                priority: None,
            },
        },
        true,
    )
    .await
    .unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(&json_output).expect("queue list --json output must be valid JSON");
    let parsed_rows = parsed
        .as_array()
        .expect("queue list --json is a JSON array");
    assert_eq!(parsed_rows.len(), expected_rows.len());
    assert_eq!(
        parsed_rows[0]["message_id"].as_str().unwrap(),
        expected_rows[0].message_id
    );
    assert_eq!(
        parsed_rows[0]["source_account"].as_str().unwrap(),
        expected_rows[0].source_account
    );
    assert_eq!(
        parsed_rows[0]["sequence"].as_i64().unwrap(),
        expected_rows[0].sequence
    );
    assert_eq!(
        parsed_rows[0]["priority"].as_str().unwrap(),
        expected_rows[0].priority
    );
    assert_eq!(
        parsed_rows[0]["enqueued_at"].as_u64().unwrap(),
        expected_rows[0].enqueued_at
    );

    // `db summary --json` likewise round-trips every field the plain
    // assembly function produces.
    let expected_summary = db_summary(&db).await.unwrap();
    let summary_json = dispatch(
        &db,
        &Command::Db {
            action: DbAction::Summary,
        },
        true,
    )
    .await
    .unwrap();
    let parsed_summary: serde_json::Value =
        serde_json::from_str(&summary_json).expect("db summary --json output must be valid JSON");
    assert_eq!(
        parsed_summary["queued_envelopes_count"].as_i64().unwrap(),
        expected_summary.queued_envelopes_count
    );
    assert_eq!(
        parsed_summary["settlement_status_count"].as_i64().unwrap(),
        expected_summary.settlement_status_count
    );
    assert_eq!(
        parsed_summary["sequence_reservations_count"]
            .as_i64()
            .unwrap(),
        expected_summary.sequence_reservations_count
    );
    assert_eq!(
        parsed_summary["conflicts_count"].as_i64().unwrap(),
        expected_summary.conflicts_count
    );
    assert_eq!(
        parsed_summary["unresolved_conflicts_count"]
            .as_i64()
            .unwrap(),
        expected_summary.unresolved_conflicts_count
    );
    assert_eq!(
        parsed_summary["oldest_queued_at"].as_u64(),
        expected_summary.oldest_queued_at
    );
    assert_eq!(
        parsed_summary["newest_queued_at"].as_u64(),
        expected_summary.newest_queued_at
    );
    assert_eq!(expected_summary.queued_envelopes_count, 1);
    assert_eq!(expected_summary.conflicts_count, 1);
    assert_eq!(expected_summary.unresolved_conflicts_count, 1);
}
