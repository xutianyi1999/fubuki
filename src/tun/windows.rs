use std::io::{Error, ErrorKind, Result};
use std::process::Command;
use std::time::Duration;

use simple_wintun::adapter::{WintunAdapter, WintunStream};

use crate::tun::TunDevice;
use crate::TunIpAddr;

const ADAPTER_NAME: &str = "Wintun";
const TUNNEL_TYPE: &str = "proxy";
const ADAPTER_GUID: &str = "{248B1B2B-94FA-0E20-150F-5C2D2FB4FBF9}";
//1MB
const ADAPTER_BUFF_SIZE: u32 = 0x100000;

pub struct Wintun {
    session: WintunStream<'static>,
    _adapter: WintunAdapter,
}

impl Wintun {
    pub(super) fn create(mtu: usize, ip_addrs: &[TunIpAddr]) -> Result<Wintun> {
        // drop old wintun adapter
        {
            let _ = WintunAdapter::open_adapter(ADAPTER_NAME);
        }

        //try to fix the stuck
        std::thread::sleep(Duration::from_millis(100));
        let adapter = WintunAdapter::create_adapter(ADAPTER_NAME, TUNNEL_TYPE, ADAPTER_GUID)?;

        for TunIpAddr { ip, netmask } in ip_addrs {
            let status = Command::new("netsh")
                .args([
                    "interface",
                    "ip",
                    "add",
                    "address",
                    ADAPTER_NAME,
                    ip.to_string().as_str(),
                    netmask.to_string().as_str(),
                ])
                .output()?
                .status;

            if !status.success() {
                return Err(Error::new(ErrorKind::Other, "Failed to add tun ip address"));
            }
        }

        let status = Command::new("netsh")
            .args([
                "interface",
                "ipv4",
                "set",
                "subinterface",
                ADAPTER_NAME,
                &format!("mtu={}", mtu),
            ])
            .output()?
            .status;

        if !status.success() {
            return Err(Error::new(ErrorKind::Other, "Failed to set tun mtu"));
        }

        // TODO self reference
        let session: WintunStream<'static> =
            unsafe { std::mem::transmute(adapter.start_session(ADAPTER_BUFF_SIZE)?) };
        Ok(Wintun {
            session,
            _adapter: adapter,
        })
    }
}

impl TunDevice for Wintun {
    fn send_packet(&self, packet: &[u8]) -> Result<()> {
        const ERROR_BUFFER_OVERFLOW: i32 = 111;

        loop {
            match self.session.write_packet(packet) {
                Err(e) if e.raw_os_error() == Some(ERROR_BUFFER_OVERFLOW) => continue,
                res => return res,
            }
        }
    }

    fn recv_packet(&self, buff: &mut [u8]) -> Result<usize> {
        let len = self.session.read_packet(buff)?;
        Ok(len)
    }
}
