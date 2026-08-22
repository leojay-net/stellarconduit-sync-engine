//! Library backing for the `sync-engine-cli` binary
//! ([`src/bin/sync-engine-cli.rs`](../../src/bin/sync-engine-cli.rs)): a
//! read-only inspector for a `SyncEngineDb` SQLite file.
//!
//! The argument parsing and data-assembly logic lives here, rather than in
//! the binary itself, specifically so integration tests (which can only
//! depend on this crate's library target, not on a `[[bin]]`) can exercise
//! it directly against a `SyncEngineDb` built the same way the rest of this
//! crate's tests build one — see `tests/integration/cli_test.rs`.

use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;

use crate::errors::SyncEngineError;
use crate::queue::TxPriority;
use crate::storage::SyncEngineDb;

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("invalid message id '{0}': expected 64 hex characters (32 bytes)")]
    InvalidMessageId(String),
    #[error(transparent)]
    SyncEngine(#[from] SyncEngineError),
    #[error("failed to serialize output as JSON: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Parser, Debug)]
#[command(
    name = "sync-engine-cli",
    about = "Read-only inspector for a SyncEngineDb SQLite file",
    version
)]
pub struct Cli {
    /// Path to the SyncEngineDb SQLite file to inspect.
    #[arg(long, value_name = "PATH")]
    pub db_path: String,

    /// Emit machine-readable JSON instead of a human-readable table.
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Inspect the outbound envelope queue.
    Queue {
        #[command(subcommand)]
        action: QueueAction,
    },
    /// Inspect settlement status and history for a queued envelope.
    Settlement {
        #[command(subcommand)]
        action: SettlementAction,
    },
    /// Inspect detected double-spend conflicts.
    Conflicts {
        #[command(subcommand)]
        action: ConflictsAction,
    },
    /// Inspect the database as a whole.
    Db {
        #[command(subcommand)]
        action: DbAction,
    },
}

#[derive(Subcommand, Debug)]
pub enum QueueAction {
    /// List queued envelopes, optionally filtered by account and/or priority.
    List {
        /// Only show envelopes queued by this Stellar source account.
        #[arg(long)]
        account: Option<String>,
        /// Only show envelopes at this priority tier.
        #[arg(long, value_enum)]
        priority: Option<PriorityArg>,
    },
}

#[derive(Subcommand, Debug)]
pub enum SettlementAction {
    /// Show current settlement status and full history for one message id
    /// (hex-encoded, e.g. from `queue list`'s output).
    Status { message_id: String },
}

#[derive(Subcommand, Debug)]
pub enum ConflictsAction {
    /// List recorded double-spend conflicts.
    List {
        /// Only show conflicts not yet resolved.
        #[arg(long)]
        unresolved_only: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum DbAction {
    /// Show row counts per table and queue age extremes.
    Summary,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum PriorityArg {
    Low,
    Normal,
    Emergency,
}

impl From<PriorityArg> for TxPriority {
    fn from(p: PriorityArg) -> Self {
        match p {
            PriorityArg::Low => TxPriority::Low,
            PriorityArg::Normal => TxPriority::Normal,
            PriorityArg::Emergency => TxPriority::Emergency,
        }
    }
}

fn priority_label(priority: TxPriority) -> &'static str {
    match priority {
        TxPriority::Low => "low",
        TxPriority::Normal => "normal",
        TxPriority::Emergency => "emergency",
    }
}

fn parse_message_id(hex_str: &str) -> Result<[u8; 32], CliError> {
    let bytes =
        hex::decode(hex_str).map_err(|_| CliError::InvalidMessageId(hex_str.to_string()))?;
    <[u8; 32]>::try_from(bytes).map_err(|_| CliError::InvalidMessageId(hex_str.to_string()))
}

// ── Data assembly ───────────────────────────────────────────────────────
//
// Each function below assembles a plain, `Serialize`-able view of the
// requested data from `SyncEngineDb`. Rendering (table vs. JSON) is kept
// separate so both output modes are guaranteed to draw from exactly the
// same underlying values (see the acceptance criteria that `--json` must
// contain the same information as the human-readable form).

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct QueueEntryView {
    pub message_id: String,
    pub source_account: String,
    pub sequence: i64,
    pub priority: String,
    pub enqueued_at: u64,
}

pub async fn queue_list(
    db: &SyncEngineDb,
    account: Option<&str>,
    priority: Option<TxPriority>,
) -> Result<Vec<QueueEntryView>, CliError> {
    let mut records = db.list_queued_envelopes().await?;
    records.sort_by(|a, b| {
        a.enqueued_at
            .cmp(&b.enqueued_at)
            .then_with(|| a.envelope.message_id.cmp(&b.envelope.message_id))
    });

    Ok(records
        .into_iter()
        .filter(|r| match account {
            Some(acc) => r.source_account == acc,
            None => true,
        })
        .filter(|r| match priority {
            Some(p) => r.priority == p,
            None => true,
        })
        .map(|r| QueueEntryView {
            message_id: hex::encode(r.envelope.message_id),
            source_account: r.source_account,
            sequence: r.sequence,
            priority: priority_label(r.priority).to_string(),
            enqueued_at: r.enqueued_at,
        })
        .collect())
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HistoryEntryView {
    pub from_status: String,
    pub to_status: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SettlementStatusView {
    pub message_id: String,
    pub current_status: Option<String>,
    pub history: Vec<HistoryEntryView>,
}

pub async fn settlement_status(
    db: &SyncEngineDb,
    message_id_hex: &str,
) -> Result<SettlementStatusView, CliError> {
    let message_id = parse_message_id(message_id_hex)?;
    let current_status = db
        .get_settlement_status(message_id)
        .await?
        .map(|s| s.as_str().to_string());
    let history = db
        .history_for(message_id)
        .await?
        .into_iter()
        .map(|h| HistoryEntryView {
            from_status: h.from_status,
            to_status: h.to_status,
            timestamp: h.timestamp,
        })
        .collect();

    Ok(SettlementStatusView {
        message_id: hex::encode(message_id),
        current_status,
        history,
    })
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ConflictView {
    pub id: i64,
    pub source_account: String,
    pub sequence: i64,
    pub envelope_a: String,
    pub envelope_b: String,
    pub detected_at: u64,
    pub resolved: bool,
}

pub async fn conflicts_list(
    db: &SyncEngineDb,
    unresolved_only: bool,
) -> Result<Vec<ConflictView>, CliError> {
    let all = db.list_all_conflicts().await?;
    Ok(all
        .into_iter()
        .filter(|c| !unresolved_only || !c.resolved)
        .map(|c| ConflictView {
            id: c.id,
            source_account: c.source_account,
            sequence: c.sequence,
            envelope_a: hex::encode(c.envelope_a),
            envelope_b: hex::encode(c.envelope_b),
            detected_at: c.detected_at,
            resolved: c.resolved,
        })
        .collect())
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct DbSummaryView {
    pub queued_envelopes_count: i64,
    pub settlement_status_count: i64,
    pub sequence_reservations_count: i64,
    pub conflicts_count: i64,
    pub unresolved_conflicts_count: i64,
    pub oldest_queued_at: Option<u64>,
    pub newest_queued_at: Option<u64>,
}

pub async fn db_summary(db: &SyncEngineDb) -> Result<DbSummaryView, CliError> {
    let s = db.summary().await?;
    Ok(DbSummaryView {
        queued_envelopes_count: s.queued_envelopes_count,
        settlement_status_count: s.settlement_status_count,
        sequence_reservations_count: s.sequence_reservations_count,
        conflicts_count: s.conflicts_count,
        unresolved_conflicts_count: s.unresolved_conflicts_count,
        oldest_queued_at: s.oldest_queued_at,
        newest_queued_at: s.newest_queued_at,
    })
}

// ── Rendering ────────────────────────────────────────────────────────────

fn to_json<T: Serialize>(value: &T) -> Result<String, CliError> {
    Ok(serde_json::to_string_pretty(value)?)
}

/// Render a simple, aligned table. Shared by every subcommand's
/// human-readable output.
fn render_table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.len());
        }
    }

    let mut out = String::new();
    let render_row = |cells: &[String], widths: &[usize]| -> String {
        cells
            .iter()
            .enumerate()
            .map(|(i, c)| format!("{:width$}", c, width = widths[i]))
            .collect::<Vec<_>>()
            .join("  ")
    };

    let header_cells: Vec<String> = headers.iter().map(|h| h.to_string()).collect();
    out.push_str(render_row(&header_cells, &widths).trim_end());
    out.push('\n');
    out.push_str(
        &widths
            .iter()
            .map(|w| "-".repeat(*w))
            .collect::<Vec<_>>()
            .join("  "),
    );
    out.push('\n');

    if rows.is_empty() {
        out.push_str("(no rows)\n");
    } else {
        for row in rows {
            out.push_str(render_row(row, &widths).trim_end());
            out.push('\n');
        }
    }

    out
}

fn render_queue_table(rows: &[QueueEntryView]) -> String {
    render_table(
        &[
            "MESSAGE_ID",
            "SOURCE_ACCOUNT",
            "SEQUENCE",
            "PRIORITY",
            "ENQUEUED_AT",
        ],
        &rows
            .iter()
            .map(|r| {
                vec![
                    r.message_id.clone(),
                    r.source_account.clone(),
                    r.sequence.to_string(),
                    r.priority.clone(),
                    r.enqueued_at.to_string(),
                ]
            })
            .collect::<Vec<_>>(),
    )
}

fn render_settlement_status(view: &SettlementStatusView) -> String {
    let mut out = String::new();
    out.push_str(&format!("message_id:     {}\n", view.message_id));
    out.push_str(&format!(
        "current_status: {}\n",
        view.current_status.as_deref().unwrap_or("(untracked)")
    ));
    out.push_str("history:\n");
    out.push_str(&render_table(
        &["FROM_STATUS", "TO_STATUS", "TIMESTAMP"],
        &view
            .history
            .iter()
            .map(|h| {
                vec![
                    h.from_status.clone(),
                    h.to_status.clone(),
                    h.timestamp.to_string(),
                ]
            })
            .collect::<Vec<_>>(),
    ));
    out
}

fn render_conflicts_table(rows: &[ConflictView]) -> String {
    render_table(
        &[
            "ID",
            "SOURCE_ACCOUNT",
            "SEQUENCE",
            "ENVELOPE_A",
            "ENVELOPE_B",
            "DETECTED_AT",
            "RESOLVED",
        ],
        &rows
            .iter()
            .map(|c| {
                vec![
                    c.id.to_string(),
                    c.source_account.clone(),
                    c.sequence.to_string(),
                    c.envelope_a.clone(),
                    c.envelope_b.clone(),
                    c.detected_at.to_string(),
                    c.resolved.to_string(),
                ]
            })
            .collect::<Vec<_>>(),
    )
}

fn render_summary(view: &DbSummaryView) -> String {
    format!(
        "queued_envelopes:      {}\n\
         settlement_status:     {}\n\
         sequence_reservations: {}\n\
         conflicts:             {} ({} unresolved)\n\
         oldest_queued_at:      {}\n\
         newest_queued_at:      {}\n",
        view.queued_envelopes_count,
        view.settlement_status_count,
        view.sequence_reservations_count,
        view.conflicts_count,
        view.unresolved_conflicts_count,
        view.oldest_queued_at
            .map(|v| v.to_string())
            .unwrap_or_else(|| "(none)".to_string()),
        view.newest_queued_at
            .map(|v| v.to_string())
            .unwrap_or_else(|| "(none)".to_string()),
    )
}

// ── Dispatch ─────────────────────────────────────────────────────────────

/// Run `command` against `db`, returning the fully rendered output (table or
/// JSON, per `json`). Split out from [`run`] so tests can drive it directly
/// against an in-memory or fixture `SyncEngineDb` without touching argv or a
/// real file path.
pub async fn dispatch(
    db: &SyncEngineDb,
    command: &Command,
    json: bool,
) -> Result<String, CliError> {
    match command {
        Command::Queue {
            action: QueueAction::List { account, priority },
        } => {
            let rows = queue_list(db, account.as_deref(), priority.map(Into::into)).await?;
            if json {
                to_json(&rows)
            } else {
                Ok(render_queue_table(&rows))
            }
        }
        Command::Settlement {
            action: SettlementAction::Status { message_id },
        } => {
            let view = settlement_status(db, message_id).await?;
            if json {
                to_json(&view)
            } else {
                Ok(render_settlement_status(&view))
            }
        }
        Command::Conflicts {
            action: ConflictsAction::List { unresolved_only },
        } => {
            let rows = conflicts_list(db, *unresolved_only).await?;
            if json {
                to_json(&rows)
            } else {
                Ok(render_conflicts_table(&rows))
            }
        }
        Command::Db {
            action: DbAction::Summary,
        } => {
            let view = db_summary(db).await?;
            if json {
                to_json(&view)
            } else {
                Ok(render_summary(&view))
            }
        }
    }
}

/// Open the database at `cli.db_path` and run `cli.command` against it.
/// Thin entry point for [`crate`]'s `sync-engine-cli` binary; see
/// [`dispatch`] for the testable core.
pub async fn run(cli: Cli) -> Result<String, CliError> {
    let db = SyncEngineDb::init(&cli.db_path).await?;
    dispatch(&db, &cli.command, cli.json).await
}
