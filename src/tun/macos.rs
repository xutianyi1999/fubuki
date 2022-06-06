use std::cell::UnsafeCell;
use std::io;
use std::io::{Error, ErrorKind, Result};
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::process::Command;
use std::time::Duration;
use tun::Device;

use crate::tun::TunDevice;
use crate::TunIpAddr;

const MAX_LENGTH: u8 = 32;

pub fn cut_addr(addr: Ipv4Addr, len: u8) -> Ipv4Addr {
    if len > MAX_LENGTH {
        panic!("Network length error")
    } else {
        let right_len = MAX_LENGTH - len;
        let bits = u32::from(addr) as u64;
        let new_bits = (bits >> right_len) << right_len;

        Ipv4Addr::from(new_bits as u32)
    }
}

fn add_route(ip: Ipv4Addr, netmask: Ipv4Addr) -> Result<()> {
    let len = u32::from(netmask).count_ones();
    let subnet_addr = cut_addr(ip, len as u8);

    let status = Command::new("route")
        .args([
            "-n",
            "add",
            "-net",
            subnet_addr.to_string().as_str(),
            "-netmask",
            netmask.to_string().as_str(),
            ip.to_string().as_str(),
        ])
        .output()?
        .status;

    if status.success() {
        Ok(())
    } else {
        Err(Error::new(ErrorKind::Other, "Failed to add route"))
    }
}

pub struct Macostun {
    fd: UnsafeCell<tun::platform::Device>,
}

unsafe impl Sync for Macostun {}

impl Macostun {
    pub(super) fn create(mtu: usize, ip_addrs: &[TunIpAddr]) -> Result<Macostun> {
        let mut config = tun::Configuration::default();
        config
            .address(ip_addrs[0].ip)
            .netmask(ip_addrs[0].netmask)
            .mtu(mtu as i32)
            .up();

        let device = tun::create(&config).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        std::thread::sleep(Duration::from_secs(1));

        add_route(ip_addrs[0].ip, ip_addrs[0].netmask)?;

        for TunIpAddr { ip, netmask } in &ip_addrs[1..] {
            let count = u32::from(*netmask).count_ones();
            let subnet = cut_addr(*ip, count as u8);

            let status = Command::new("ifconfig")
                .args([
                    device.name(),
                    "alias",
                    format!("{}/{}", ip, count).as_str(),
                    subnet.to_string().as_str(),
                ])
                .output()?
                .status;

            if !status.success() {
                return Err(Error::new(ErrorKind::Other, "Failed to add tun ip address"));
            }

            add_route(*ip, *netmask)?;
        }

        Ok(Macostun {
            fd: UnsafeCell::new(device),
        })
    }
}

impl TunDevice for Macostun {
    fn send_packet(&self, packet: &[u8]) -> Result<()> {
        let mut buff = vec![0u8; packet.len() + 4];
        buff[..3].copy_from_slice(&[0u8; 3]);
        buff[3] = 2;
        buff[4..].copy_from_slice(packet);
        let fd = unsafe { &mut *self.fd.get() };
        fd.write(&buff)?;
        Ok(())
    }

    fn recv_packet(&self, buff: &mut [u8]) -> Result<usize> {
        let fd = unsafe { &mut *self.fd.get() };
        let len = fd.read(buff)?;
        buff.rotate_left(4);
        Ok(len - 4)
    }
}
