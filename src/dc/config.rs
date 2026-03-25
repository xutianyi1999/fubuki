use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use ipnet::Ipv4Net;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DcConfig {
    /// UUID string → 16-byte network id
    pub network_id: String,
    pub psk: String,
    /// Virtual interface address and prefix, e.g. `"10.200.1.5/24"`.
    pub virtual_net: Ipv4Net,
    #[serde(default = "default_listen_udp")]
    pub listen_udp: u16,
    #[serde(default)]
    pub display_name: String,
    pub bootstrap: Vec<String>,
    /// STUN `host:port` servers for reflexive address (same UDP socket as mesh). Empty disables.
    #[serde(default = "default_stun_servers")]
    pub stun_servers: Vec<String>,
    pub node_id_path: Option<PathBuf>,
}

fn default_listen_udp() -> u16 {
    22400
}

fn default_stun_servers() -> Vec<String> {
    vec!["stun.l.google.com:19302".to_string()]
}

impl DcConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let f = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
        serde_json::from_reader(f).context("parse dc.json")
    }

    pub fn network_id_bytes(&self) -> Result<[u8; 16]> {
        let u = uuid::Uuid::from_str(self.network_id.trim())
            .map_err(|e| anyhow!("invalid network_id UUID: {e}"))?;
        Ok(*u.as_bytes())
    }

    pub fn bootstrap_addrs(&self) -> Result<Vec<SocketAddr>> {
        let mut out = Vec::with_capacity(self.bootstrap.len());
        for s in &self.bootstrap {
            let a = s
                .parse::<SocketAddr>()
                .with_context(|| format!("bootstrap parse: {s}"))?;
            out.push(a);
        }
        Ok(out)
    }

    pub fn default_node_id_path(&self) -> PathBuf {
        let name = format!("dc-{}.id", self.network_id);
        dirs_config().join(name)
    }

    /// Persisted member-row version (see `row_version` module).
    pub fn row_version_state_path(&self) -> PathBuf {
        let name = format!("dc-{}-row.json", self.network_id);
        dirs_config().join(name)
    }
}

fn dirs_config() -> PathBuf {
    if let Some(d) = std::env::var_os("FUBUKI_DC_STATE_DIR") {
        return PathBuf::from(d);
    }
    dirs::config_dir()
        .map(|p| p.join("fubuki"))
        .unwrap_or_else(|| PathBuf::from(".fubuki-dc"))
}
