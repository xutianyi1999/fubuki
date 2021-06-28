use std::io::Result;
use std::net::Ipv4Addr;

#[cfg(target_os = "windows")]
mod windows;

pub trait Rx: Send {
    fn send_packet(&mut self, packet: &[u8]) -> Result<()>;
}

pub trait Tx: Send {
    fn recv_packet(&mut self, buff: &mut [u8]) -> Result<usize>;
}

pub trait TunDevice: Rx + Tx + Send {
    fn split(self: Box<Self>) -> (Box<dyn Rx>, Box<dyn Tx>);
}

pub fn create_device(address: Ipv4Addr, netmask: Ipv4Addr) -> Result<Box<dyn TunDevice>> {
    #[cfg(target_os = "windows")]
        {
            Ok(Box::new(windows::Wintun::create(address, netmask)?))
        }
}