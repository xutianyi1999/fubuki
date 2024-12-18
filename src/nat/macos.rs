use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::Write;
use std::net::SocketAddrV4;
use std::process::{Command, Stdio};

use anyhow::{anyhow, Result};
use ipnet::Ipv4Net;
use parking_lot::Mutex;

use crate::common::net::get_interface_addr;

#[allow(unused)]
pub fn check_available() -> bool {
    crate::common::cmd_exists("pfctl").is_ok()
}

static RECORDS: Mutex<Vec<Record>> = Mutex::new(Vec::new());

#[derive(Clone, Eq, PartialEq)]
struct Record {
    if_name: String,
    src_cidr: Ipv4Net,
    dst_cidr: Ipv4Net,
}

impl Display for Record {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "nat on {} from {} to {} -> {}", self.if_name, self.src_cidr, self.dst_cidr, self.if_name)
    }
}

pub fn add_nat(ranges: &[Ipv4Net], src: Ipv4Net) -> Result<()> {
    let mut records = RECORDS.lock();

    let status = Command::new("sysctl")
        .args([
            "-w", "net.inet.ip.forwarding=1"
        ])
        .stderr(Stdio::inherit())
        .output()?
        .status;

    if !status.success() {
        return Err(anyhow!("enable net.inet.ip.forwarding option failed"));
    }

    let dir = tempfile::tempdir()?;
    let file_path = dir.path().join("fubuki-pf-nat.conf");
    let mut file = File::create(file_path.as_path())?;

    let ifs = netconfig::list_interfaces().map_err(|e| anyhow!(e.to_string()))?;

    for range in ranges {
        let lan = get_interface_addr(SocketAddrV4::new(range.broadcast(), 1).into())?;
        let mut if_name = None;

        'top: for interface in &ifs {
            for ip in interface.addresses().map_err(|e| anyhow!(e.to_string()))? {
                if ip.addr() == lan {
                    if_name = Some(interface.name().map_err(|e| anyhow!(e.to_string()))?);
                    break 'top;
                }
            }
        }

        let record = match if_name {
            None => return Err(anyhow!("cannot found interface")),
            Some(if_name) => {
                Record {
                    if_name,
                    src_cidr: src,
                    dst_cidr: *range,
                }
            }
        };

        writeln!(file, "{}", record)?;
        records.push(record);
    }

    let status = Command::new("pfctl")
        .args([
            "-Ef", file_path.to_str().ok_or_else(|| anyhow!("cannot get fubuki-pf-nat.conf path"))?
        ])
        .stderr(Stdio::inherit())
        .output()?
        .status;

    if !status.success() {
        return Err(anyhow!("add nat record failed"));
    }

    Ok(())
}

pub fn del_nat(ranges: &[Ipv4Net], src: Ipv4Net) -> Result<()> {
    let mut records = RECORDS.lock();

    *records = records.iter()
        .filter(|record| !(ranges.contains(&record.dst_cidr) && record.src_cidr == src))
        .cloned()
        .collect();

    let dir = tempfile::tempdir()?;
    let file_path = dir.path().join("fubuki-pf-nat.conf");
    let mut file = File::create(file_path.as_path())?;

    for record in &*records {
        writeln!(file, "{}", record)?;
    }

    let status = Command::new("pfctl")
        .args([
            "-Ef", file_path.to_str().ok_or_else(|| anyhow!("cannot get fubuki-pf-nat.conf path"))?
        ])
        .stderr(Stdio::inherit())
        .output()?
        .status;

    if !status.success() {
        return Err(anyhow!("remove nat record failed"));
    }

    Ok(())
}