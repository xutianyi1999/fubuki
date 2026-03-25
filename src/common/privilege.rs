//! Privilege check: root on Linux/macOS, Administrator on Windows.

use anyhow::{anyhow, Result};

/// Root on Linux / macOS, Administrator on Windows.
pub fn require_elevated_for_node() -> Result<()> {
    if is_elevated() {
        return Ok(());
    }
    #[cfg(target_os = "windows")]
    return Err(anyhow!(
        "Fubuki requires Administrator privileges. Run PowerShell or cmd as Administrator, then try again."
    ));
    #[cfg(target_os = "linux")]
    return Err(anyhow!(
        "Fubuki requires root (e.g. sudo fubuki daemon -c ./dc.json)."
    ));
    #[cfg(target_os = "macos")]
    return Err(anyhow!(
        "Fubuki requires root (e.g. sudo fubuki daemon -c ./dc.json)."
    ));
}

fn is_elevated() -> bool {
    #[cfg(target_os = "windows")]
    return is_elevated_windows();
    #[cfg(all(unix, not(target_os = "windows")))]
    return is_elevated_unix();
}

#[cfg(target_os = "windows")]
fn is_elevated_windows() -> bool {
    use std::process::Command;
    use std::process::Stdio;
    let status = Command::new("net")
        .args(["session"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match status {
        Ok(s) => s.success(),
        Err(_) => false,
    }
}

#[cfg(all(unix, not(target_os = "windows")))]
fn is_elevated_unix() -> bool {
    unsafe { libc::geteuid() == 0 }
}
