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

use crate::queue::TxPriority;

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
