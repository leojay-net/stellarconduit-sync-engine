//! Local diagnostic CLI for inspecting a `SyncEngineDb` SQLite file: what's
//! queued, an envelope's settlement history, unresolved conflicts, and
//! overall table row counts. Read-only — see `src/cli.rs` for the argument
//! parsing and data assembly this binary just wires up to argv and stdout.

use clap::Parser;

use stellarconduit_sync_engine::cli::{run, Cli};

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(output) => print!("{output}"),
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(1);
        }
    }
}
