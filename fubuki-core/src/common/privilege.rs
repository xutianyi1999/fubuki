//! Privilege check for node daemon: root on Unix, Administrator on Windows.

use anyhow::{anyhow, Result};

/// Returns `Ok(())` if the process has the privileges required to run the node
/// (root on Linux/macOS, Administrator on Windows). Otherwise returns an error
/// with a message telling the user how to elevate.
pub fn require_elevated_for_node() -> Result<()> {
    if is_elevated() {
        return Ok(());
    }
    #[cfg(target_os = "windows")]
    return Err(anyhow!(
        "Fubuki node requires Administrator privileges. Please run the command prompt or PowerShell as Administrator, then run the command again."
    ));
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    return Err(anyhow!(
        "Fubuki node requires root privileges. Please run with sudo or as root (e.g. sudo fubuki node daemon ./node.json)."
    ));
}

fn is_elevated() -> bool {
    #[cfg(target_os = "windows")]
    return is_elevated_windows();
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    return is_elevated_unix();
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    return true;
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn is_elevated_unix() -> bool {
    unsafe { libc::geteuid() == 0 }
}
