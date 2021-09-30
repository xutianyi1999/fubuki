use std::io::{Error, ErrorKind, Result};
use std::net::Ipv4Addr;
use std::process::Command;
use std::ptr::null_mut;
use std::sync::Arc;

use simple_wintun::{raw, ReadResult};
use simple_wintun::adapter::{WintunAdapter, WintunStream};

use crate::common::net::proto::MTU;
use crate::tun::{Rx, TunDevice, Tx};

const POOL_NAME: &str = "Wintun";
const ADAPTER_NAME: &str = "proxy";
const ADAPTER_GUID: &str = "{248B1B2B-94FA-0E20-150F-5C2D2FB4FBF9}";
//1MB
const ADAPTER_BUFF_SIZE: u32 = 1048576;

pub struct Wintun {
    adapter: WintunAdapter,
    session: WintunStream,
}

impl Wintun {
    pub fn create(address: Ipv4Addr, netmask: Ipv4Addr) -> Result<Wintun> {
        let netmask_count = get_netmask_bit_count(netmask);
        WintunAdapter::initialize();

        if let Ok(adapter) = WintunAdapter::get_adapter(POOL_NAME, ADAPTER_NAME) {
            adapter.delete_adapter()?;
        }

        let adapter = WintunAdapter::create_adapter(POOL_NAME, ADAPTER_NAME, ADAPTER_GUID)?;
        adapter.set_ipaddr(&address.to_string(), netmask_count)?;

        let status = Command::new("netsh")
            .args(vec!["interface", "ipv4", "set", "subinterface", ADAPTER_NAME, &format!("mtu={}", MTU), "store=persistent"])
            .output()?
            .status;

        if !status.success() {
            return Err(Error::new(ErrorKind::Other, "Failed to set tun mtu"));
        }

        let session = adapter.open_adapter(ADAPTER_BUFF_SIZE)?;

        Ok(Wintun { adapter, session })
    }
}

unsafe impl Send for Wintun {}

unsafe impl Send for WintunRx {}

unsafe impl Send for WintunTx {}

impl Drop for Wintun {
    fn drop(&mut self) {
        raw::close_adapter(self.session.session);
        self.session.session = null_mut();
        raw::delete_adapter(self.adapter.adapter).unwrap()
    }
}

impl Tx for Wintun {
    fn send_packet(&mut self, packet: &[u8]) -> Result<()> {
        self.session.write_packet(packet)
    }
}

impl Rx for Wintun {
    fn recv_packet(&mut self, buff: &mut [u8]) -> Result<usize> {
        let res = self.session.read_packet(buff)?;

        match res {
            ReadResult::Success(len) => Ok(len),
            ReadResult::NotEnoughSize(_) => Ok(0)
        }
    }
}

impl TunDevice for Wintun {
    fn split(self: Box<Self>) -> (Box<dyn Tx>, Box<dyn Rx>) {
        let wintun = Arc::new(*self);
        let wintun_tx = WintunTx { wintun: wintun.clone() };
        let wintun_rx = WintunRx { wintun };

        (Box::new(wintun_rx), Box::new(wintun_tx))
    }
}

struct WintunTx {
    wintun: Arc<Wintun>,
}

struct WintunRx {
    wintun: Arc<Wintun>,
}

impl Tx for WintunRx {
    fn send_packet(&mut self, packet: &[u8]) -> Result<()> {
        let p_wintun: *const Wintun = &*self.wintun;
        let ref_wintun = unsafe { &mut *(p_wintun as *mut Wintun) };
        ref_wintun.send_packet(packet)
    }
}

impl Rx for WintunTx {
    fn recv_packet(&mut self, buff: &mut [u8]) -> Result<usize> {
        let p_wintun: *const Wintun = &*self.wintun;
        let ref_wintun = unsafe { &mut *(p_wintun as *mut Wintun) };
        ref_wintun.recv_packet(buff)
    }
}

fn get_netmask_bit_count(ipv4: Ipv4Addr) -> u8 {
    let octets = ipv4.octets();
    let mut count = 0;

    for x in octets.iter() {
        let mut bits = to_bits(*x);
        bits.reverse();

        for x in bits.iter() {
            if *x == 1 {
                count += 1;
            } else {
                return count;
            }
        }
    };
    count
}

fn to_bits(v: u8) -> [u8; 8] {
    let mut bits = [0u8; 8];

    for x in 0..8 {
        let b = (v << x) >> 7;
        bits[7 - x] = b;
    };
    bits
}