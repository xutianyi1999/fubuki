use std::io::Result;
use std::net::Ipv4Addr;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "linux")]
mod linux;

pub trait Tx: Send {
    fn send_packet(&mut self, packet: &[u8]) -> Result<()>;
}

pub trait Rx: Send {
    fn recv_packet(&mut self, buff: &mut [u8]) -> Result<usize>;
}

pub trait TunDevice: Tx + Rx + Send {
    fn split(self: Box<Self>) -> (Box<dyn Tx>, Box<dyn Rx>);
}

pub fn create_device(address: Ipv4Addr, netmask: Ipv4Addr) -> Result<Box<dyn TunDevice>> {
    #[cfg(target_os = "windows")]
        {
            Ok(Box::new(windows::Wintun::create(address, netmask)?))
        }
    #[cfg(target_os = "linux")]
        {
            Ok(Box::new(linux::Linuxtun::create(address, netmask)?))
        }
}