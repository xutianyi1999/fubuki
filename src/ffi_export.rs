use std::ffi::{c_char, c_void, CStr, CString};
use std::future::Future;
use std::net::Ipv4Addr;
use std::ptr::null_mut;
use std::slice;

use anyhow::Result;
use tokio::runtime::Runtime;

use crate::{Key, logger_init, node, NodeConfig, NodeConfigFinalize};
use crate::common::allocator::{alloc, Bytes};
use crate::tun::TunDevice;

struct Bridge {
    ctx: *mut c_void,
    fubuki_to_if_fn: extern "C" fn(packet: *const u8, len: usize, ctx: *mut c_void),
    add_addr_fn: extern "C" fn(addr: [u8; 4], netmask: [u8; 4], ctx: *mut c_void),
    delete_addr_fn: extern "C" fn(addr: [u8; 4], netmask: [u8; 4], ctx: *mut c_void),
    if_to_fubuki_rx: flume::Receiver<Bytes>,
    device_index: u32,
}

unsafe impl Send for Bridge {}

unsafe impl Sync for Bridge {}

impl TunDevice for Bridge {
    type SendFut<'a> = std::future::Ready<Result<()>>;
    type RecvFut<'a> = impl Future<Output=Result<usize>> + 'a;

    fn send_packet<'a>(&'a self, packet: &'a [u8]) -> Self::SendFut<'a> {
        (self.fubuki_to_if_fn)(packet.as_ptr(), packet.len(), self.ctx);
        std::future::ready(Ok(()))
    }

    fn recv_packet<'a>(&'a self, buff: &'a mut [u8]) -> Self::RecvFut<'a> {
        let rx = &self.if_to_fubuki_rx;
        async {
            let bytes = rx.recv_async().await?;
            buff[..bytes.len()].copy_from_slice(&bytes);
            Ok(bytes.len())
        }
    }

    fn set_mtu(&self, _mtu: usize) -> Result<()> {
        Ok(())
    }

    fn add_addr(&self, addr: Ipv4Addr, netmask: Ipv4Addr) -> Result<()> {
        (self.add_addr_fn)(addr.octets(), netmask.octets(), self.ctx);
        Ok(())
    }

    fn delete_addr(&self, addr: Ipv4Addr, netmask: Ipv4Addr) -> Result<()> {
        (self.delete_addr_fn)(addr.octets(), netmask.octets(), self.ctx);
        Ok(())
    }

    fn get_index(&self) -> u32 {
        self.device_index
    }
}

#[no_mangle]
pub extern "C" fn if_to_fubuki(handle: *const Handle, packet: *const u8, len: usize) {
    let handle = unsafe { &*handle };
    let packet = unsafe { slice::from_raw_parts(packet, len) };
    let mut buff = alloc(packet.len());
    buff.copy_from_slice(packet);

    let _ = handle.if_to_fubuki_tx.send(buff);
}

pub struct Handle {
    _rt: Runtime,
    if_to_fubuki_tx: flume::Sender<Bytes>,
}

fn fubuki_init_inner(
    node_config_json: *const c_char,
    ctx: *mut c_void,
    fubuki_to_if_fn: extern "C" fn(packet: *const u8, len: usize, ctx: *mut c_void),
    add_addr_fn: extern "C" fn(addr: [u8; 4], netmask: [u8; 4], ctx: *mut c_void),
    delete_addr_fn: extern "C" fn(addr: [u8; 4], netmask: [u8; 4], ctx: *mut c_void),
    device_index: u32,
) -> Result<Box<Handle>> {
    let s = unsafe { CStr::from_ptr(node_config_json) }.to_bytes();
    let config: NodeConfig = serde_json::from_slice(s)?;
    let c: NodeConfigFinalize<Key> = NodeConfigFinalize::try_from(config)?;
    let rt = Runtime::new()?;
    logger_init()?;

    let (tx, rx) = flume::bounded(100);

    let bridge = Bridge {
        ctx,
        fubuki_to_if_fn,
        add_addr_fn,
        delete_addr_fn,
        device_index,
        if_to_fubuki_rx: rx,
    };

    rt.spawn(
        async move {
            if let Err(e) = node::start(c, bridge).await {
                error!("{:?}", e);
            }
        }
    );

    let h = Handle {
        _rt: rt,
        if_to_fubuki_tx: tx,
    };
    Ok(Box::new(h))
}

#[no_mangle]
pub extern "C" fn fubuki_start(
    node_config_json: *const c_char,
    ctx: *mut c_void,
    fubuki_to_if_fn: extern "C" fn(packet: *const u8, len: usize, ctx: *mut c_void),
    add_addr_fn: extern "C" fn(addr: [u8; 4], netmask: [u8; 4], ctx: *mut c_void),
    delete_addr_fn: extern "C" fn(addr: [u8; 4], netmask: [u8; 4], ctx: *mut c_void),
    device_index: u32,
    error: *mut c_char,
) -> *mut Handle {
    match fubuki_init_inner(
        node_config_json,
        ctx,
        fubuki_to_if_fn,
        add_addr_fn,
        delete_addr_fn,
        device_index,
    ) {
        Ok(v) => Box::into_raw(v),
        Err(e) => {
            let e = CString::new(e.to_string()).unwrap();
            let src = e.as_bytes_with_nul();
            unsafe { std::ptr::copy(src.as_ptr(), error as *mut u8, src.len()) };
            null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn fubuki_stop(handle: *mut Handle) {
    let _ = unsafe { Box::from_raw(handle) };
}
