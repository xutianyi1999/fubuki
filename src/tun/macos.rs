use std::net::Ipv4Addr;
use crate::tun::TunDevice;

pub struct Macostun {
}

impl TunDevice for Macostun {
    type SendFut<'a> where Self: 'a = ();
    type RecvFut<'a> where Self: 'a = ();

    fn send_packet<'a>(&'a self, packet: &'a [u8]) -> Self::SendFut<'a> {
        todo!()
    }

    fn recv_packet<'a>(&'a self, buff: &'a mut [u8]) -> Self::RecvFut<'a> {
        todo!()
    }

    fn set_mtu(&self, mtu: usize) -> anyhow::Result<()> {
        todo!()
    }

    fn add_addr(&self, addr: Ipv4Addr, netmask: Ipv4Addr) -> anyhow::Result<()> {
        todo!()
    }

    fn delete_addr(&self, addr: Ipv4Addr, netmask: Ipv4Addr) -> anyhow::Result<()> {
        todo!()
    }

    fn get_index(&self) -> u32 {
        todo!()
    }
}