use std::future::Future;
use anyhow::Result;
use std::net::Ipv4Addr;
use std::sync::Arc;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "windows")]
mod windows;

pub trait TunDevice {
    type SendFut<'a>: Future<Output = Result<()>> + Send + Sync
    where
        Self: 'a;

    type RecvFut<'a>: Future<Output = Result<usize>> + Send + Sync
    where
        Self: 'a;

    fn send_packet<'a>(&'a self, packet: &'a [u8]) -> Self::SendFut<'a>;

    fn recv_packet<'a>(&'a self, buff: &'a mut [u8]) -> Self::RecvFut<'a>;

    fn set_mtu(&self, mtu: usize) -> Result<()>;

    fn add_addr(&self, addr: Ipv4Addr, netmask: Ipv4Addr) -> Result<()>;

    fn delete_addr(&self, addr: Ipv4Addr, netmask: Ipv4Addr) -> Result<()>;

    fn get_index(&self) -> u32;
}

impl<T: TunDevice> TunDevice for Arc<T> {
    type SendFut<'a> = T::SendFut<'a> where Self: 'a;
    type RecvFut<'a> = T::RecvFut<'a> where Self: 'a;

    fn send_packet<'a>(&'a self, packet: &'a [u8]) -> Self::SendFut<'a> {
        (**self).send_packet(packet)
    }

    fn recv_packet<'a>(&'a self, buff: &'a mut [u8]) -> Self::RecvFut<'a> {
        (**self).recv_packet(buff)
    }

    fn set_mtu(&self, mtu: usize) -> Result<()> {
        (**self).set_mtu(mtu)
    }

    fn add_addr(&self, addr: Ipv4Addr, netmask: Ipv4Addr) -> Result<()> {
        (**self).add_addr(addr, netmask)
    }

    fn delete_addr(&self, addr: Ipv4Addr, netmask: Ipv4Addr) -> Result<()> {
        (**self).delete_addr(addr, netmask)
    }

    fn get_index(&self) -> u32 {
        (**self).get_index()
    }
}

pub(crate) fn create_device() -> Result<impl TunDevice + Send + Sync> {
    let tun;

    #[cfg(target_os = "windows")]
    {
        tun = windows::Wintun::create()?;
    }
    #[cfg(target_os = "linux")]
    {
        tun = linux::Linuxtun::create()?;
    }

    Ok(tun)
}