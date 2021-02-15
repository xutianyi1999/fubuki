use std::io::{Read, Write};
use std::net::IpAddr;

use tokio::io::Result;
use tun::platform::Device;
use tun::platform::posix::{Reader, Writer};

use crate::common::res::StdResConvert;
use crate::tun::{Rx, TunDevice, Tx};

pub fn create_device(address: IpAddr, netmask: IpAddr) -> Result<TunDevice<Device, Writer, Reader>> {
    let mut config = tun::Configuration::default();
    config.address(address)
        .netmask(netmask)
        .up();

    config.platform(|config| {
        config.packet_information(false);
    });

    let device = tun::create(&config).res_convert(|_| String::from("Create tun failed"))?;
    let (rx, tx) = device.split();
    Ok(TunDevice::new(device, tx, rx))
}

impl Tx for Writer {
    fn send_packet(&mut self, buff: &[u8]) -> Result<()> {
        self.write_all(buff)
    }
}

impl Rx for Reader {
    fn recv_packet(&mut self, buff: &mut [u8]) -> Result<usize> {
        self.read(buff)
    }
}

