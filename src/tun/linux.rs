use std::cell::UnsafeCell;
use std::io;
use std::io::{Error, ErrorKind, Result};
use std::io::{Read, Write};
use std::process::Command;
use tun::Device;

use crate::tun::TunDevice;
use crate::TunIpAddr;

pub struct Linuxtun {
    fd: UnsafeCell<tun::platform::Device>,
}

unsafe impl Sync for Linuxtun {}

impl Linuxtun {
    pub(super) fn create(mtu: usize, ip_addrs: &[TunIpAddr]) -> Result<Linuxtun> {
        let mut config = tun::Configuration::default();
        config
            .address(ip_addrs[0].ip)
            .netmask(ip_addrs[0].netmask)
            .mtu(mtu as i32)
            .platform(|config| {
                config.packet_information(false);
            })
            .up();

        let device = tun::create(&config).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let tun_name = device.name();

        for TunIpAddr { ip, netmask } in &ip_addrs[1..] {
            let count = u32::from(*netmask).count_ones();

            let status = Command::new("ip")
                .args([
                    "addr",
                    "add",
                    format!("{}/{}", ip, count).as_str(),
                    "dev",
                    tun_name,
                ])
                .output()?
                .status;

            if !status.success() {
                return Err(Error::new(ErrorKind::Other, "Failed to add tun ip address"));
            }
        }

        Ok(Linuxtun {
            fd: UnsafeCell::new(device),
        })
    }
}

impl TunDevice for Linuxtun {
    fn send_packet(&self, packet: &[u8]) -> Result<()> {
        let fd = unsafe { &mut *self.fd.get() };
        fd.write(packet)?;
        Ok(())
    }

    fn recv_packet(&self, buff: &mut [u8]) -> Result<usize> {
        let fd = unsafe { &mut *self.fd.get() };
        fd.read(buff)
    }
}
