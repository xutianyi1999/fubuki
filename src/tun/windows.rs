use std::io::{Error, ErrorKind, Result};
use std::net::Ipv4Addr;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use simple_wintun::adapter::{WintunAdapter, WintunStream};
use simple_wintun::ReadResult;

use crate::common::net::proto::MTU;
use crate::tun::TunDevice;
use crate::TunConfig;

const ADAPTER_NAME: &str = "Wintun";
const TUNNEL_TYPE: &str = "proxy";
const ADAPTER_GUID: &str = "{248B1B2B-94FA-0E20-150F-5C2D2FB4FBF9}";
//1MB
const ADAPTER_BUFF_SIZE: u32 = 1048576;

pub struct Wintun {
    session: WintunStream<'static>,
    _adapter: WintunAdapter,
}

impl Wintun {
    pub fn create(tun_config: Vec<TunConfig>) -> Result<Wintun> {
        // drop old wintun adapter
        { WintunAdapter::open_adapter(ADAPTER_NAME) }

        //try to fix the stuck
        std::thread::sleep(Duration::from_millis(100));
        let adapter = WintunAdapter::create_adapter(ADAPTER_NAME, TUNNEL_TYPE, ADAPTER_GUID)?;

        for TunConfig { ip, netmask } in tun_config {
            let status = Command::new("netsh")
                .args(["interface", "ip", "add", "address", ADAPTER_NAME, ip.to_string().as_str(), netmask.to_string().as_str()])
                .output()?
                .status;

            if !status.success() {
                return Err(Error::new(ErrorKind::Other, "Failed to add tun ip address"));
            }
        }

        let status = Command::new("netsh")
            .args(["interface", "ipv4", "set", "subinterface", ADAPTER_NAME, &format!("mtu={}", MTU), "store=persistent"])
            .output()?
            .status;

        if !status.success() {
            return Err(Error::new(ErrorKind::Other, "Failed to set tun mtu"));
        }

        let session: WintunStream<'static> = unsafe { std::mem::transmute(adapter.start_session(ADAPTER_BUFF_SIZE)?) };
        Ok(Wintun { session, _adapter: adapter })
    }
}

impl TunDevice for Wintun {
    fn send_packet(&self, packet: &[u8]) -> Result<()> {
        self.session.write_packet(packet)
    }

    fn recv_packet(&self, buff: &mut [u8]) -> Result<usize> {
        let res = self.session.read_packet(buff)?;

        match res {
            ReadResult::Success(len) => Ok(len),
            ReadResult::NotEnoughSize(_) => Ok(0)
        }
    }
}