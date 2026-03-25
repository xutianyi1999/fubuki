use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use backon::{ExponentialBuilder, Retryable};
use ipnet::Ipv4Net;
use serde::Deserialize;
use tokio::time::Instant;

/// `dc.json` root: PSK mesh identity, overlay addressing, and discovery endpoints.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DcConfig {
    /// Network UUID string; hashed with PSK to derive keys and to namespace persisted state.
    pub network_id: String,
    /// Pre-shared key for this mesh; never sent on the wire (used in HKDF).
    pub psk: String,
    /// Virtual TUN IPv4 address and prefix, e.g. `"10.200.1.5/24"`.
    pub virtual_net: Ipv4Net,
    /// Local UDP port bound for FBDC frames (`0.0.0.0:listen_udp`).
    #[serde(default = "default_listen_udp")]
    pub listen_udp: u16,
    /// Optional short name shown to peers; empty uses OS hostname.
    #[serde(default)]
    pub display_name: String,
    /// Initial peers as `host:port` or numeric `SocketAddr`; resolved at startup for first MEMBER_ANNOUNCE.
    pub bootstrap: Vec<String>,
    /// STUN `host:port` servers for reflexive (NAT) address on the same UDP socket as the mesh.
    #[serde(default = "default_stun_servers")]
    pub stun_servers: Vec<String>,
    /// If set, persist this instance's stable member UUID (text) here; otherwise use a default path under the config directory.
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

    /// Resolve each bootstrap entry: numeric `SocketAddr` strings parse directly;
    /// `host:port` hostnames are resolved via DNS (same idea as `stun_servers`).
    pub async fn bootstrap_addrs(&self) -> Result<Vec<SocketAddr>> {
        let mut out = Vec::with_capacity(self.bootstrap.len());
        for s in &self.bootstrap {
            let s = s.trim();
            let a = if let Ok(a) = s.parse::<SocketAddr>() {
                a
            } else {
                resolve_host_port_udp(s)
                    .await
                    .with_context(|| format!("bootstrap parse: {s}"))?
            };
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

/// DNS for bootstrap peers can be briefly unavailable (e.g. Docker Compose parallel start).
/// Retries use [`backon::ExponentialBuilder`] (100 ms–10 s, factor 2, jitter) under a wall-clock cap.
const BOOTSTRAP_DNS_BUDGET: Duration = Duration::from_secs(90);

async fn resolve_host_port_udp(s: &str) -> Result<SocketAddr> {
    let (host, port_s) = s
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("expected host:port or a numeric socket address"))?;
    let port: u16 = port_s
        .parse()
        .with_context(|| format!("bootstrap UDP port: {port_s}"))?;
    lookup_host_bootstrap(host, port)
        .await
        .with_context(|| format!("bootstrap DNS lookup: {host}"))
}

async fn lookup_host_bootstrap(host: &str, port: u16) -> Result<SocketAddr> {
    let start = Instant::now();
    let host_owned = host.to_string();
    let builder = ExponentialBuilder::new()
        .with_min_delay(Duration::from_millis(100))
        .with_max_delay(Duration::from_secs(10))
        .with_max_times(24)
        .with_jitter();

    let outcome = (|| async {
        match tokio::net::lookup_host((host_owned.as_str(), port)).await {
            Ok(addrs) => pick_socket_addr(addrs).ok_or_else(|| {
                format!("no addresses returned for {host}:{port}")
            }),
            Err(e) => Err(e.to_string()),
        }
    })
    .retry(builder)
    .when(|_| start.elapsed() < BOOTSTRAP_DNS_BUDGET)
    .notify(|err: &String, dur: Duration| {
        log::warn!(
            "bootstrap DNS: {host}:{port} not ready yet ({err}); retry in {:?} (elapsed {:?})",
            dur,
            start.elapsed()
        );
    })
    .adjust(|_err, dur| {
        let elapsed = start.elapsed();
        if elapsed >= BOOTSTRAP_DNS_BUDGET {
            return None;
        }
        let remaining = BOOTSTRAP_DNS_BUDGET.saturating_sub(elapsed);
        dur.map(|d| d.min(remaining)).filter(|d| !d.is_zero())
    })
    .await;

    match outcome {
        Ok(a) => {
            if start.elapsed() > Duration::from_millis(50) {
                log::info!(
                    "bootstrap DNS: resolved {host}:{port} to {a} after {:?}",
                    start.elapsed()
                );
            }
            Ok(a)
        }
        Err(e) => Err(anyhow!(
            "bootstrap DNS: gave up on {host}:{port} after {:?}: {e}",
            BOOTSTRAP_DNS_BUDGET
        )),
    }
}

fn pick_socket_addr(
    addrs: impl Iterator<Item = SocketAddr>,
) -> Option<SocketAddr> {
    let mut first = None;
    for a in addrs {
        if matches!(a, SocketAddr::V4(_)) {
            return Some(a);
        }
        first.get_or_insert(a);
    }
    first
}

fn dirs_config() -> PathBuf {
    if let Some(d) = std::env::var_os("FUBUKI_DC_STATE_DIR") {
        return PathBuf::from(d);
    }
    dirs::config_dir()
        .map(|p| p.join("fubuki"))
        .unwrap_or_else(|| PathBuf::from(".fubuki-dc"))
}
