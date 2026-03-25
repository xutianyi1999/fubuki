use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Subcommand)]
pub enum Command {
    /// Start mesh VPN (decentralized; see doc/decentralized-mvp.md)
    #[command(visible_alias = "start")]
    Daemon {
        /// Path to dc.json
        #[arg(short, long, value_name = "FILE")]
        config_path: PathBuf,
    },
    /// Update fubuki to the latest GitHub release
    Update {
        #[arg(short = 'o', long, default_value = "xutianyi1999", value_name = "OWNER")]
        repo_owner: String,
        #[arg(short = 'r', long, default_value = "fubuki", value_name = "REPO")]
        repo_name: String,
    },
}

#[derive(Parser)]
#[command(
    name = "fubuki",
    version,
    about = "Mesh VPN over TUN (decentralized, Windows / Linux / macOS)",
    author,
    next_line_help = true,
)]
pub struct Args {
    #[command(subcommand)]
    pub command: Command,
}
