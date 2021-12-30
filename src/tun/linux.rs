use std::io;
use std::io::{Read, Write};
use std::io::Result;
use std::net::Ipv4Addr;

use tun::platform::Device;
use tun::platform::posix::{Reader, Writer};

use crate::common::net::proto::MTU;
use crate::tun::{Rx, TunDevice, Tx};

pub struct Linuxtun {
    fd: Device,
}

impl Linuxtun {
    pub fn create(address: Ipv4Addr, netmask: Ipv4Addr) -> Result<Linuxtun> {
        let mut config = tun::Configuration::default();
        config.address(address)
            .netmask(netmask)
            .mtu(MTU as i32)
            .up();

        config.platform(|config| {
            config.packet_information(false);
        });

        Ok(Linuxtun {
            fd: tun::create(&config).map_err(|e| {
                io::Error::new(io::ErrorKind::Other, e)
            })?
        })
    }
}

struct LinuxtunTx {
    tx: Writer,
}

struct LinuxtunRx {
    rx: Reader,
}

impl Tx for LinuxtunTx {
    fn send_packet(&mut self, packet: &[u8]) -> Result<()> {
        self.tx.write(packet)?;
        Ok(())
    }
}

impl Rx for LinuxtunRx {
    fn recv_packet(&mut self, buff: &mut [u8]) -> Result<usize> {
        self.rx.read(buff)
    }
}

impl Rx for Linuxtun {
    fn recv_packet(&mut self, buff: &mut [u8]) -> Result<usize> {
        self.fd.read(buff)
    }
}

impl Tx for Linuxtun {
    fn send_packet(&mut self, packet: &[u8]) -> Result<()> {
        self.fd.write(packet)?;
        Ok(())
    }
}

impl TunDevice for Linuxtun {
    fn split(self) -> (Box<dyn Tx>, Box<dyn Rx>) {
        let (rx, tx) = self.fd.split();
        (Box::new(LinuxtunTx { tx }), Box::new(LinuxtunRx { rx }))
    }
}