use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Top-level CLI action.
#[derive(Subcommand)]
pub enum Command {
    /// Start mesh VPN (decentralized; see doc/decentralized-mvp.md)
    #[command(visible_alias = "start")]
    Daemon {
        /// Path to `dc.json` for this peer.
        #[arg(short, long, value_name = "FILE")]
        config_path: PathBuf,
    },
    /// Update fubuki to the latest GitHub release
    Update {
        /// GitHub user or organization that owns the repository.
        #[arg(short = 'o', long, default_value = "xutianyi1999", value_name = "OWNER")]
        repo_owner: String,
        /// GitHub repository name (without `.git`).
        #[arg(short = 'r', long, default_value = "fubuki", value_name = "REPO")]
        repo_name: String,
    },
}

/// Root clap parser: dispatches the `Command` subcommand enum.
#[derive(Parser)]
#[command(
    name = "fubuki",
    version,
    about = "Mesh VPN over TUN (decentralized, Windows / Linux / macOS)",
    author,
    next_line_help = true,
)]
pub struct Args {
    /// Subcommand to run (`daemon` or `update`).
    #[command(subcommand)]
    pub command: Command,
}
