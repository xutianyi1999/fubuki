//! Persistent [`HelloBody::row_version`] / directory `version`: bumps when peer-visible row changes.

use std::fs;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::config::DcConfig;

#[derive(Serialize, Deserialize)]
struct RowState {
    version: u64,
    fingerprint: [u8; 32],
}

/// Hash of config-driven row fields (not runtime hostname fallback for `display_name`).
fn row_fingerprint(cfg: &DcConfig) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(cfg.virtual_net.addr().octets());
    h.update([cfg.virtual_net.prefix_len()]);
    h.update(cfg.listen_udp.to_be_bytes());
    h.update(cfg.display_name.trim().as_bytes());
    let mut stun = cfg.stun_servers.clone();
    stun.sort();
    for s in stun {
        h.update(s.as_bytes());
        h.update(b"\n");
    }
    h.finalize().into()
}

/// Load version for current fingerprint; if fingerprint changed since last run, increment and persist.
pub fn load_or_bump(cfg: &DcConfig) -> Result<u64> {
    load_or_bump_inner(cfg, false)
}

fn load_or_bump_inner(cfg: &DcConfig, retried: bool) -> Result<u64> {
    let path = cfg.row_version_state_path();
    let fp = row_fingerprint(cfg);

    let (next, write) = if path.exists() {
        let text = match fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => {
                warn!("dc: row version state unreadable {}: {e}", path.display());
                if !retried {
                    let _ = fs::remove_file(&path);
                    return load_or_bump_inner(cfg, true);
                }
                return Err(e).with_context(|| format!("read {}", path.display()));
            }
        };
        let state: RowState = match serde_json::from_str(&text) {
            Ok(s) => s,
            Err(e) => {
                warn!("dc: row version state corrupt {}: {e}", path.display());
                if !retried {
                    let _ = fs::remove_file(&path);
                    return load_or_bump_inner(cfg, true);
                }
                return Err(e).with_context(|| format!("parse {}", path.display()));
            }
        };
        if state.fingerprint == fp {
            (state.version, false)
        } else {
            let v = state.version.saturating_add(1).max(1);
            (v, true)
        }
    } else {
        (1u64, true)
    };

    if write {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).ok();
        }
        let state = RowState {
            version: next,
            fingerprint: fp,
        };
        let text = serde_json::to_string_pretty(&state).context("serialize row state")?;
        fs::write(&path, format!("{text}\n")).with_context(|| format!("write {}", path.display()))?;
    }

    Ok(next)
}

