use std::process::Command;

use anyhow::{anyhow, Result};
use ipnet::Ipv4Net;

#[cfg(target_os = "windows")]
pub fn add_nat(_ranges: &[Ipv4Net], src: Ipv4Net) -> Result<()> {
    let output = Command::new("powershell")
        .args([
            "New-NetNat",
            "-Name",
            &format!("fubuki-{}", src),
            "-InternalIPInterfaceAddressPrefix",
            src.to_string().as_str(),
        ])
        .output()?;

    if !output.status.success() {
        return Err(anyhow!("Failed to add nat"));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn del_nat(_ranges: &[Ipv4Net], src: Ipv4Net) -> Result<()> {
    let status = Command::new("powershell")
        .args([
            "Remove-NetNat",
            "-Name",
            &format!("fubuki-{}", src),
            "-Confirm:$false"
        ])
        .output()?
        .status;

    if !status.success() {
        return Err(anyhow!("Failed to remove nat"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn add_nat(ranges: &[Ipv4Net], src: Ipv4Net) -> Result<()> {
    for dst in ranges {
        let status = Command::new("iptables")
            .args([
                "-t",
               "nat",
                "-A",
                "POSTROUTING",
                "-j",
                "MASQUERADE",
                "-d",
                dst.to_string().as_str(),
                "-s",
                src.to_string().as_str()
            ])
            .output()?
            .status;

        if !status.success() {
            return Err(anyhow!("Failed to add nat"));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn del_nat(ranges: &[Ipv4Net], src: Ipv4Net) -> Result<()> {
    for dst in ranges {
        let status = Command::new("iptables")
            .args([
                "-t",
                "nat",
                "-D",
                "POSTROUTING",
                "-j",
                "MASQUERADE",
                "-d",
                dst.to_string().as_str(),
                "-s",
                src.to_string().as_str()
            ])
            .output()?
            .status;

        if !status.success() {
            return Err(anyhow!("Failed to set nat"));
        }
    }
    Ok(())
}
