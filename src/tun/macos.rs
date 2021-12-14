use std::io;
use std::io::{Read, Write};
use std::io::Result;
use std::net::Ipv4Addr;

use tun::platform::Device;
use tun::platform::posix::{Reader, Writer};

use crate::common::net::proto::MTU;
use crate::tun::{Rx, TunDevice, Tx};

pub struct Mactun {
    fd: Device,
}

impl Mactun {
    pub fn create(address: Ipv4Addr, netmask: Ipv4Addr) -> Result<Mactun> {
        let mut config = tun::Configuration::default();
        config.address(address)
            .netmask(netmask)
            .mtu(MTU as i32)
            .up();

        Ok(Mactun {
            fd: tun::create(&config).map_err(|e| {
                io::Error::new(io::ErrorKind::Other, e.to_string())
            })?
        })
    }
}

struct MactunTx {
    tx: Writer,
}

struct MactunRx {
    rx: Reader,
}

impl Tx for MactunTx {
    fn send_packet(&mut self, packet: &[u8]) -> Result<()> {
        self.tx.write(packet)?;
        Ok(())
    }
}

impl Rx for MactunRx {
    fn recv_packet(&mut self, buff: &mut [u8]) -> Result<usize> {
        self.rx.read(buff)
    }
}

impl Rx for Mactun {
    fn recv_packet(&mut self, buff: &mut [u8]) -> Result<usize> {
        self.fd.read(buff)
    }
}

impl Tx for Mactun {
    fn send_packet(&mut self, packet: &[u8]) -> Result<()> {
        self.fd.write(packet)?;
        Ok(())
    }
}

impl TunDevice for Mactun {
    fn split(self) -> (Box<dyn Tx>, Box<dyn Rx>) {
        let (rx, tx) = self.fd.split();
        (Box::new(MactunTx { tx }), Box::new(MactunRx { rx }))
    }
}