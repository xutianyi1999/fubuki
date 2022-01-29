use std::io::Result;
use std::net::Ipv4Addr;

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

pub fn create_device(tun_config: Vec<TunConfig>) -> Result<impl TunDevice> {
    #[cfg(target_os = "windows")]
        {
            Ok(windows::Wintun::create(tun_config)?)
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