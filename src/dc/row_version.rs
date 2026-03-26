//! Persistent directory row `version` (published in [`MEMBER_ANNOUNCE`](crate::dc::msg::DirectoryEntryWire::version)); bumps when peer-visible row changes.

use std::fs;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::config::DcConfig;

/// On-disk state next to `dc.json` tracking directory row version vs config fingerprint.
#[derive(Serialize, Deserialize)]
struct RowState {
    /// Last published [`super::msg::DirectoryEntryWire::version`].
    version: u64,
    /// SHA-256 over stable config fields; bump `version` when this changes.
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
        fs::write(&path, format!("{text}\n"))
            .with_context(|| format!("write {}", path.display()))?;
    }

    Ok(next)
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::Mutex;

    use super::super::config::DcConfig;
    use super::load_or_bump;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_state_dir<R>(run: impl FnOnce(&Path) -> R) -> R {
        let _guard = ENV_LOCK.lock().expect("row_version test env lock");
        let dir = tempfile::TempDir::new().expect("tempdir");
        let prev = std::env::var_os("FUBUKI_DC_STATE_DIR");
        std::env::set_var("FUBUKI_DC_STATE_DIR", dir.path());
        let out = run(dir.path());
        match &prev {
            Some(v) => std::env::set_var("FUBUKI_DC_STATE_DIR", v),
            None => std::env::remove_var("FUBUKI_DC_STATE_DIR"),
        }
        out
    }

    fn cfg_row_test(network_id: &str, display_name: &str, stun_servers: Vec<String>) -> DcConfig {
        let j = format!(
            r#"{{
                "network_id": "{network_id}",
                "psk": "row-test-psk",
                "virtual_net": "10.88.1.1/24",
                "listen_udp": 33100,
                "display_name": "{display_name}",
                "bootstrap": [],
                "stun_servers": {}
            }}"#,
            serde_json::to_string(&stun_servers).expect("stun json")
        );
        serde_json::from_str(&j).expect("dc config")
    }

    #[test]
    fn first_run_writes_version_one() {
        with_state_dir(|_| {
            let c = cfg_row_test("33333333-3333-3333-3333-333333333333", "n1", vec![]);
            assert_eq!(load_or_bump(&c).expect("bump"), 1);
            assert_eq!(load_or_bump(&c).expect("again"), 1);
        });
    }

    #[test]
    fn display_name_change_bumps_version() {
        with_state_dir(|_| {
            let c1 = cfg_row_test("44444444-4444-4444-4444-444444444444", "alice", vec![]);
            assert_eq!(load_or_bump(&c1).unwrap(), 1);
            let c2 = cfg_row_test("44444444-4444-4444-4444-444444444444", "bob", vec![]);
            assert_eq!(load_or_bump(&c2).unwrap(), 2);
            assert_eq!(load_or_bump(&c2).unwrap(), 2);
        });
    }

    #[test]
    fn stun_server_order_same_fingerprint() {
        with_state_dir(|_| {
            let id = "55555555-5555-5555-5555-555555555555";
            let c1 = cfg_row_test(
                id,
                "x",
                vec!["stun.b.example:3478".into(), "stun.a.example:3478".into()],
            );
            let c2 = cfg_row_test(
                id,
                "x",
                vec!["stun.a.example:3478".into(), "stun.b.example:3478".into()],
            );
            assert_eq!(load_or_bump(&c1).unwrap(), 1);
            assert_eq!(load_or_bump(&c2).unwrap(), 1);
        });
    }

    #[test]
    fn corrupt_state_file_recovers_to_version_one() {
        with_state_dir(|root| {
            let c = cfg_row_test("66666666-6666-6666-6666-666666666666", "y", vec![]);
            let path = c.row_version_state_path();
            assert!(path.starts_with(root));
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, "not-json {{{\n").unwrap();
            assert_eq!(load_or_bump(&c).unwrap(), 1);
            assert_eq!(load_or_bump(&c).unwrap(), 1);
        });
    }
}
