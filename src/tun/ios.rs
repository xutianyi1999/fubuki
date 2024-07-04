use std::future::Future;
use std::net::Ipv4Addr;
use std::os::fd::RawFd;

use anyhow::Result;
use tun::AsyncDevice;

use crate::common::allocator::alloc;
use crate::tun::TunDevice;

pub struct IOStun {
    inner: AsyncDevice
}

pub fn create(fd: RawFd) -> Result<IOStun> {
    let mut config = tun::Configuration::default();
    config.raw_fd(fd);

    let tun = tun::create_as_async(&config)?;
    Ok(IOStun {inner: tun})
}

impl TunDevice for IOStun {
    type SendFut<'a> = impl Future<Output = Result<()>> + 'a;
    type RecvFut<'a> = impl Future<Output = Result<usize>> + 'a;

    fn send_packet<'a>(&'a self, packet: &'a [u8]) -> Self::SendFut<'a> {
        let fd = &self.inner;

        async {
            let mut buff = alloc(packet.len() + 4);
            buff[..3].copy_from_slice(&[0u8; 3]);
            buff[3] = 2;
            buff[4..].copy_from_slice(packet);
            fd.send(&buff).await?;
            Ok(())
        }
    }

    fn recv_packet<'a>(&'a self, buff: &'a mut [u8]) -> Self::RecvFut<'a> {
        let fd = &self.inner;

        async {
            let len = fd.recv(buff).await?;
            buff.rotate_left(4);
            Ok(len - 4)
        }
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