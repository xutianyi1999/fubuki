#[cfg(not(target_os = "macos"))]
use std::process::{Command, Stdio};

use anyhow::{anyhow, Result};
use ipnet::Ipv4Net;

#[cfg(target_os = "windows")]
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
        return Err(anyhow!("add nat record failed"));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
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
        return Err(anyhow!("remove nat record failed"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn add_nat(ranges: &[Ipv4Net], src: Ipv4Net) -> Result<()> {
    let status = Command::new("sysctl")
        .args([
            "-w", "net.ipv4.ip_forward=1"
        ])
        .stderr(Stdio::inherit())
        .output()?
        .status;

    if !status.success() {
        return Err(anyhow!("open net.ipv4.ip_forward option failed"));
    }

    for dst in ranges {
        let status = Command::new("iptables")
            .args([
                "-t", "nat",
                "-A", "POSTROUTING",
                "-j", "MASQUERADE",
                "-d", dst.to_string().as_str(),
                "-s", src.to_string().as_str()
            ])
            .stderr(Stdio::inherit())
            .output()?
            .status;

        if !status.success() {
            return Err(anyhow!("add nat record failed"));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn del_nat(ranges: &[Ipv4Net], src: Ipv4Net) -> Result<()> {
    for dst in ranges {
        let status = Command::new("iptables")
            .args([
                "-t", "nat",
                "-D", "POSTROUTING",
                "-j", "MASQUERADE",
                "-d", dst.to_string().as_str(),
                "-s", src.to_string().as_str()
            ])
            .stderr(Stdio::inherit())
            .output()?
            .status;

        if !status.success() {
            return Err(anyhow!("remove nat record failed"));
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn add_nat(_ranges: &[Ipv4Net], _src: Ipv4Net) -> Result<()> {
    Err(anyhow!("macos does not support nat"))
}

#[cfg(target_os = "macos")]
pub fn del_nat(_ranges: &[Ipv4Net], _src: Ipv4Net) -> Result<()> {
    Err(anyhow!("macos does not support nat"))
}