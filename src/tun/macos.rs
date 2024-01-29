use std::cell::UnsafeCell;
use std::future::Future;
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};

use ahash::{HashSet, HashSetExt};
use anyhow::{anyhow, Result};
use ipnet::{IpNet, Ipv4Net};
use netconfig::Interface;
use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tun::Device;

use crate::common::allocator::alloc;
use crate::tun::TunDevice;

pub struct Macostun {
    ips: Mutex<HashSet<Ipv4Addr>>,
    fd: UnsafeCell<tun::AsyncDevice>,
    inter: Interface,
}

unsafe impl Sync for Macostun {}

pub fn create() -> Result<Macostun> {
    let mut config = tun::Configuration::default();
    config.up();

    let device = tun::create_as_async(&config)?;
    let device_name = device.get_ref().name()?;

    let inter = netconfig::Interface::try_from_name(&device_name).map_err(|e| anyhow!(e.to_string()))?;

    Ok(Macostun {
        ips: Mutex::new(HashSet::new()),
        fd: UnsafeCell::new(device),
        inter,
    })
}

impl TunDevice for Macostun {
    type SendFut<'a> = impl Future<Output=Result<()>> + 'a;
    type RecvFut<'a> = impl Future<Output=Result<usize>> + 'a;

    fn send_packet<'a>(&'a self, packet: &'a [u8]) -> Self::SendFut<'a> {
        let fd = unsafe { &mut *self.fd.get() };

        async {
            let mut buff = alloc(packet.len() + 4);
            buff[..3].copy_from_slice(&[0u8; 3]);
            buff[3] = 2;
            buff[4..].copy_from_slice(packet);
            fd.write(&buff).await?;
            Ok(())
        }
    }

    fn recv_packet<'a>(&'a self, buff: &'a mut [u8]) -> Self::RecvFut<'a> {
        let fd = unsafe { &mut *self.fd.get() };

        async {
            let len = fd.read(buff).await?;
            buff.rotate_left(4);
            Ok(len - 4)
        }
    }

    fn set_mtu(&self, mtu: usize) -> anyhow::Result<()> {
        let fd = unsafe { &mut *self.fd.get() };
        fd.get_mut().set_mtu(mtu as i32)?;
        Ok(())
    }

    fn add_addr(&self, addr: Ipv4Addr, netmask: Ipv4Addr) -> anyhow::Result<()> {
        let cidr = Ipv4Net::with_netmask(addr, netmask)?;
        let mut guard = self.ips.lock();

        if guard.contains(&addr) {
            return Ok(());
        }

        self.inter
            .add_address(IpNet::V4(cidr))
            .map_err(|e| anyhow!(e.to_string()))?;

        let status = Command::new("route")
            .args([
                "-n",
                "add",
                "-net",
                cidr.network().to_string().as_str(),
                "-netmask",
                netmask.to_string().as_str(),
                addr.to_string().as_str(),
            ])
            .stderr(Stdio::inherit())
            .output()?
            .status;

        if !status.success() {
            return Err(anyhow!("failed to add route"));
        }

        guard.insert(addr);
        Ok(())
    }

    fn delete_addr(&self, addr: Ipv4Addr, netmask: Ipv4Addr) -> anyhow::Result<()> {
        let cidr = Ipv4Net::with_netmask(addr, netmask)?;
        let mut guard = self.ips.lock();

        if !guard.contains(&addr) {
            return Ok(());
        }

        self.inter
            .remove_address(IpNet::V4(cidr))
            .map_err(|e| anyhow!(e.to_string()))?;

        let status = Command::new("route")
            .args([
                "-n",
                "delete",
                "-net",
                cidr.network().to_string().as_str(),
                "-netmask",
                netmask.to_string().as_str(),
                addr.to_string().as_str(),
            ])
            .stderr(Stdio::inherit())
            .output()?
            .status;

        if !status.success() {
            return Err(anyhow!("failed to delete route"));
        }

        guard.remove(&addr);
        Ok(())
    }

    fn get_index(&self) -> u32 {
        self.inter.index().expect("can't get interface index")
    }
}