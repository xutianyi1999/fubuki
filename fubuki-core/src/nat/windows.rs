use std::process::{Command, Stdio};

use anyhow::{anyhow, Result};
use ipnet::Ipv4Net;

#[allow(unused)]
pub fn check_available() -> bool {
    crate::common::cmd_exists("New-NetNat").is_ok()
}

pub fn add_nat(_ranges: &[Ipv4Net], src: Ipv4Net) -> Result<()> {
    let output = Command::new("powershell")
        .args([
            "New-NetNat",
            "-Name", &format!("fubuki-{}", src),
            "-InternalIPInterfaceAddressPrefix",
            src.to_string().as_str(),
        ])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()?;

    if !output.status.success() {
        return Err(anyhow!("Failed to add NAT record for range {}. Ensure PowerShell is available and permissions are sufficient. Command output: {:?}", src, output));
    }
    Ok(())
}

pub fn del_nat(_ranges: &[Ipv4Net], src: Ipv4Net) -> Result<()> {
    let status = Command::new("powershell")
        .args([
            "Remove-NetNat",
            "-Name", &format!("fubuki-{}", src),
            "-Confirm:$false"
        ])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()?
        .status;

    if !status.success() {
        return Err(anyhow!("Failed to remove NAT record for range {}. Ensure PowerShell is available and permissions are sufficient.", src));
    }
    Ok(())
}