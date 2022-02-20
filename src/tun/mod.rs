use std::io::Result;
use std::net::Ipv4Addr;
use std::sync::Arc;

use crate::TunConfig;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

pub trait TunDevice: Send + Sync {
    fn send_packet(&self, packet: &[u8]) -> Result<()>;

    fn recv_packet(&self, buff: &mut [u8]) -> Result<usize>;
}

impl<T: TunDevice> TunDevice for Arc<T> {
    fn send_packet(&self, packet: &[u8]) -> Result<()> {
        (**self).send_packet(packet)
    }

    fn recv_packet(&self, buff: &mut [u8]) -> Result<usize> {
        (**self).recv_packet(buff)
    }
}

pub(crate) fn create_device(tun_configs: &[TunConfig]) -> Result<impl TunDevice> {
    #[cfg(target_os = "windows")]
    {
        Ok(windows::Wintun::create(tun_configs)?)
    }
    #[cfg(target_os = "linux")]
    {
        Ok(linux::Linuxtun::create(address, netmask)?)
    }
    #[cfg(target_os = "macos")]
    {
            Ok(macos::Mactun::create(address, netmask)?)
        }
}