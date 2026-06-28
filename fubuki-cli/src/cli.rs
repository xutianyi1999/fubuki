use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Subcommand)]
pub enum NodeCmd {
    /// Start the node process (VPN client)
    #[command(visible_alias = "start")]
    Daemon {
        /// Configuration file path
        #[arg(short, long, value_name = "FILE")]
        config_path: PathBuf,
    },
    /// Query the current state of the node
    #[command(visible_alias = "status")]
    Info {
        /// API address of the node
        #[arg(short, long, default_value = "127.0.0.1:3030", value_name = "ADDR")]
        api: String,
    },
    /// Restart the running node process
    Restart {
        /// API address of the node
        #[arg(short, long, default_value = "127.0.0.1:3030", value_name = "ADDR")]
        api: String,
    },
}

#[derive(Subcommand)]
pub enum ServerCmd {
    /// Start the server process (coordinator)
    #[command(visible_alias = "start")]
    Daemon {
        /// Configuration file path
        #[arg(short, long, value_name = "FILE")]
        config_path: PathBuf,
    },
    /// Query the current state of the server
    #[command(visible_alias = "status")]
    Info {
        /// API address of the server
        #[arg(short, long, default_value = "127.0.0.1:3031", value_name = "ADDR")]
        api: String,
    },
    /// Restart the running server process
    Restart {
        /// API address of the server
        #[arg(short, long, default_value = "127.0.0.1:3031", value_name = "ADDR")]
        api: String,
    },
}

#[derive(Parser)]
#[command(
    name = "fubuki",
    version,
    about = "Lightweight mesh VPN with TUN interface",
    author,
    next_line_help = true,
)]
pub enum Args {
    /// Run the coordinator and data relay server
    Server {
        #[command(subcommand)]
        cmd: ServerCmd,
    },
    /// Run the fubuki node (VPN client)
    Node {
        #[command(subcommand)]
        cmd: NodeCmd,
    },
    /// Update fubuki to the latest release
    Update {
        /// GitHub repository owner
        #[arg(short = 'o', long, default_value = "xutianyi1999", value_name = "OWNER")]
        repo_owner: String,

        /// GitHub repository name
        #[arg(short = 'r', long, default_value = "fubuki", value_name = "REPO")]
        repo_name: String,
    },
}
