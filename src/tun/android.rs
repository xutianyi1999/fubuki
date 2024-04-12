use std::future::Future;
use std::net::Ipv4Addr;
use std::os::fd::RawFd;

use anyhow::{anyhow, Result};
use futures_util::TryFutureExt;
use tun::AsyncDevice;

use crate::tun::TunDevice;

pub struct Androidtun {
    inner: AsyncDevice
}

pub fn create(fd: RawFd) -> Result<Androidtun> {
    let mut config = tun::Configuration::default();
    config.raw_fd(fd);

    let tun = tun::create_as_async(&config)?;
    Ok(Androidtun {inner: tun})
}

impl TunDevice for Androidtun {
    type SendFut<'a> = impl Future<Output = Result<()>> + 'a;
    type RecvFut<'a> = impl Future<Output = Result<usize>> + 'a;

    fn send_packet<'a>(&'a self, packet: &'a [u8]) -> Self::SendFut<'a> {
        self.inner.send(packet)
            .map_ok(|_| ())
            .map_err(|e| anyhow!(e))
    }

    fn recv_packet<'a>(&'a self, buff: &'a mut [u8]) -> Self::RecvFut<'a> {
        self.inner.recv(buff).map_err(|e| anyhow!(e))
    }

    fn set_mtu(&self, _mtu: usize) -> Result<()> {
        Ok(())
    }

    fn add_addr(&self, _addr: Ipv4Addr, _netmask: Ipv4Addr) -> Result<()> {
        Ok(())
    }

    fn delete_addr(&self, _addr: Ipv4Addr, _netmask: Ipv4Addr) -> Result<()> {
        Ok(())
    }

    fn get_index(&self) -> u32 {
        0
    }
}