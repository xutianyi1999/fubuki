use std::net::IpAddr;

use tokio::io::Result;
use tun::platform::Device;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "Windows")]
mod windows;

pub trait Tx {
    fn send_packet(&mut self, buff: &[u8]) -> Result<()>;
}

pub trait Rx {
    fn recv_packet(&mut self, buff: &mut [u8]) -> Result<usize>;
}

#[cfg(target_os = "linux")]
pub fn create_device(address: IpAddr, netmask: IpAddr) -> Result<Device> {
    linux::create_device(address, netmask)
}