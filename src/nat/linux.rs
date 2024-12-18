use std::process::{Command, Stdio};

use anyhow::{anyhow, Result};
use ipnet::Ipv4Net;

#[allow(unused)]
pub fn check_available() -> bool {
    crate::common::cmd_exists("iptables").is_ok()
}

pub fn add_nat(ranges: &[Ipv4Net], src: Ipv4Net) -> Result<()> {
    let status = Command::new("sysctl")
        .args([
            "-w", "net.ipv4.ip_forward=1"
        ])
        .stderr(Stdio::inherit())
        .output()?
        .status;

    if !status.success() {
        return Err(anyhow!("enable net.ipv4.ip_forward option failed"));
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