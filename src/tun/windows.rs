use ahash::{HashSet, HashSetExt};
use anyhow::{anyhow, Result};
use ipnet::{IpNet, Ipv4Net};
use netconfig::sys::InterfaceExt;
use netconfig::Interface;
use parking_lot::Mutex;
use std::future::Future;
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};
use std::time::Duration;

use simple_wintun::adapter::{WintunAdapter, WintunStream};
use simple_wintun::LUID;

use crate::tun::TunDevice;

const ADAPTER_NAME: &str = "Wintun";
const TUNNEL_TYPE: &str = "proxy";
const ADAPTER_GUID: &str = "{248B1B2B-94FA-0E20-150F-5C2D2FB4FBF9}";
//1MB
const ADAPTER_BUFF_SIZE: u32 = 0x100000;

pub struct Wintun {
    ips: Mutex<HashSet<Ipv4Addr>>,
    inter: Interface,
    session: WintunStream<'static>,
    _adapter: WintunAdapter,
}

fn get_interface(luid: LUID) -> Result<Interface> {
    for x in netconfig::list_interfaces().map_err(|e| anyhow!(e.to_string()))? {
        if x.luid().map_err(|e| anyhow!(e.to_string()))? == luid {
            return Ok(x);
        }
    }
    Err(anyhow!("Not fount interface"))
}

impl Wintun {
    pub fn create() -> Result<Wintun> {
        // drop old wintun adapter
        {
            let _ = WintunAdapter::open_adapter(ADAPTER_NAME);
        }

        // to fix stuck
        std::thread::sleep(Duration::from_millis(100));
        let adapter = WintunAdapter::create_adapter(ADAPTER_NAME, TUNNEL_TYPE, ADAPTER_GUID)?;
        let interface = get_interface(adapter.get_adapter_luid())?;

        // todo self reference
        let session: WintunStream<'static> = unsafe { std::mem::transmute(adapter.start_session(ADAPTER_BUFF_SIZE)?) };

        Ok(Wintun {
            ips: Mutex::new(HashSet::new()),
            inter: interface,
            session,
            _adapter: adapter,
        })
    }
}

impl TunDevice for Wintun {
    type SendFut<'a> = std::future::Ready<Result<()>>;
    type RecvFut<'a> = impl Future<Output = Result<usize>> + 'a;

    fn send_packet(&self, packet: &[u8]) -> Self::SendFut<'_> {
        const ERROR_BUFFER_OVERFLOW: i32 = 111;

        loop {
            match self.session.write_packet(packet) {
                Err(e) if e.raw_os_error() == Some(ERROR_BUFFER_OVERFLOW) => continue,
                res => return std::future::ready(res.map_err(|e| anyhow!(e))),
            }
        }
    }

    fn recv_packet<'a>(&'a self, buff: &'a mut [u8]) -> Self::RecvFut<'a> {
        async {
            let len = self.session.async_read_packet(buff).await?;
            Ok(len)
        }
    }

    fn set_mtu(&self, mtu: usize) -> Result<()> {
        let status = Command::new("netsh")
            .args([
                "interface",
                "ipv4",
                "set",
                "subinterface",
                ADAPTER_NAME,
                &format!("mtu={}", mtu),
            ])
            .stderr(Stdio::inherit())
            .output()?
            .status;

        if !status.success() {
            return Err(anyhow!("Failed to set tun mtu"));
        }
        Ok(())
    }

    fn add_addr(&self, addr: Ipv4Addr, netmask: Ipv4Addr) -> Result<()> {
        let mut guard = self.ips.lock();

        if guard.contains(&addr) {
            return Ok(());
        }

        self.inter
            .add_address(IpNet::V4(Ipv4Net::with_netmask(addr, netmask)?))
            .map_err(|e| anyhow!(e.to_string()))?;
        guard.insert(addr);
        Ok(())
    }

    fn delete_addr(&self, addr: Ipv4Addr, netmask: Ipv4Addr) -> Result<()> {
        let mut guard = self.ips.lock();

        if !guard.contains(&addr) {
            return Ok(());
        }

        self.inter
            .remove_address(IpNet::V4(Ipv4Net::with_netmask(addr, netmask)?))
            .map_err(|e| anyhow!(e.to_string()))?;
        guard.remove(&addr);
        Ok(())
    }

    fn get_index(&self) -> u32 {
        self.inter.index().unwrap()
    }
}
