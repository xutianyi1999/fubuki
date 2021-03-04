use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use simple_wintun::adapter::{WintunAdapter, WintunStream};
use simple_wintun::ReadResult;
use tokio::io::{Error, ErrorKind, Result};

use crate::tun::{Rx, TunDevice, Tx};

const POOL_NAME: &str = "Wintun";
const ADAPTER_NAME: &str = "proxy";
const ADAPTER_GUID: &str = "{248B1B2B-94FA-0E20-150F-5C2D2FB4FBF9}";
//1MB
const ADAPTER_BUFF_SIZE: u32 = 1048576;

#[derive(Clone)]
pub struct Reader {
    session: Arc<WintunStream>
}

#[derive(Clone)]
pub struct Writer {
    session: Arc<WintunStream>
}

impl Rx for Reader {
    fn recv_packet(&mut self, buff: &mut [u8]) -> Result<usize> {
        let res = self.session.read_packet(buff)?;

        match res {
            ReadResult::Success(len) => Ok(len),
            ReadResult::NotEnoughSize(_) => Ok(0)
        }
    }
}

impl Tx for Writer {
    fn send_packet(&mut self, buff: &[u8]) -> Result<()> {
        self.session.write_packet(buff)
    }
}

pub fn create_device(address: IpAddr, netmask: IpAddr) -> Result<TunDevice<Arc<WintunStream>, Writer, Reader>> {
    let ipv4 = match netmask {
        IpAddr::V4(ipv4) => ipv4,
        _ => return Err(Error::new(ErrorKind::Other, "Netmask only supports IPV4"))
    };
    let netmask = get_netmask_bit_count(ipv4);

    WintunAdapter::initialize();
    let res = WintunAdapter::get_adapter(POOL_NAME, ADAPTER_NAME);

    if let Ok(adapter) = res {
        adapter.delete_adapter()?;
    };

    let adapter = WintunAdapter::create_adapter(POOL_NAME, ADAPTER_NAME, ADAPTER_GUID)?;

    adapter.set_ipaddr(&address.to_string(), netmask)?;
    let session = adapter.open_adapter(ADAPTER_BUFF_SIZE)?;
    let session = Arc::new(session);

    let rx = Reader { session: session.clone() };
    let tx = Writer { session: session.clone() };

    Ok(TunDevice::new(session, tx, rx))
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
