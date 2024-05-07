use std::ffi::{c_char, c_void, CStr, CString};
use std::future::Future;
use std::net::Ipv4Addr;
use std::ptr::null_mut;
use std::slice;
use std::sync::{Arc, OnceLock};

use anyhow::{anyhow, Result};
use tokio::runtime::Runtime;

use crate::node::{generic_interfaces_info, Interface};
use crate::{Key, logger_init, node, NodeConfig, NodeConfigFinalize};
use crate::common::allocator::{alloc, Bytes};
use crate::tun::TunDevice;

const FUBUKI_START_OPTIONS_VERSION1: u32 = 1;

// Android platform
#[cfg(target_os = "android")]
const FUBUKI_START_OPTIONS_VERSION2: u32 = 2;

type FubukiToIfFn = extern "C" fn(packet: *const u8, len: usize, ctx: *mut c_void);
type AddAddrFn = extern "C" fn(addr: u32, netmask: u32, ctx: *mut c_void);
type DeleteAddrFn = extern "C" fn(addr: u32, netmask: u32, ctx: *mut c_void);

struct Bridge {
    ctx: *mut c_void,
    fubuki_to_if_fn: FubukiToIfFn,
    add_addr_fn: AddAddrFn,
    delete_addr_fn: DeleteAddrFn,
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
        (self.add_addr_fn)(u32::from(addr), u32::from(netmask), self.ctx);
        Ok(())
    }

    fn delete_addr(&self, addr: Ipv4Addr, netmask: Ipv4Addr) -> Result<()> {
        (self.delete_addr_fn)(u32::from(addr), u32::from(netmask), self.ctx);
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

    let _ = handle.if_to_fubuki_tx.as_ref().unwrap().try_send(buff);
}

pub struct Handle {
    _rt: Runtime,
    if_to_fubuki_tx: Option<flume::Sender<Bytes>>,
    interfaces: Arc<OnceLock<Vec<Arc<Interface<Key>>>>>
}

fn parse_config(node_config_json: *const c_char) -> Result<NodeConfigFinalize<Key>> {
    let s = unsafe { CStr::from_ptr(node_config_json) }.to_bytes();
    let config: NodeConfig = serde_json::from_slice(s)?;
    let c: NodeConfigFinalize<Key> = NodeConfigFinalize::try_from(config)?;
    Ok(c)
}

fn fubuki_init_inner(
    node_config_json: *const c_char,
    ctx: *mut c_void,
    fubuki_to_if_fn: FubukiToIfFn,
    add_addr_fn: AddAddrFn,
    delete_addr_fn: DeleteAddrFn,
    device_index: u32,
) -> Result<Handle> {
    let c = parse_config(node_config_json)?;
    let rt = Runtime::new()?;
    logger_init()?;

    let (tx, rx) = flume::bounded(1024);

    let bridge = Bridge {
        ctx,
        fubuki_to_if_fn,
        add_addr_fn,
        delete_addr_fn,
        device_index,
        if_to_fubuki_rx: rx,
    };

    let interfaces_hook = Arc::new(OnceLock::new());
    
    rt.spawn({
        let ih = interfaces_hook.clone();

        async move {
            if let Err(e) = node::start(c, bridge, ih).await {
                error!("{:?}", e);
            }
        }
    });

    let h = Handle {
        _rt: rt,
        if_to_fubuki_tx: Some(tx),
        interfaces: interfaces_hook
    };
    Ok(h)
}

#[cfg(target_os = "android")]
fn fubuki_init_with_tun(
    node_config_json: *const c_char,
    tun_fd: std::os::fd::RawFd
) -> Result<Handle> {
    use anyhow::Context;

    let c = parse_config(node_config_json)?;
    let rt = Runtime::new()?;
    logger_init()?;

    let interfaces_hook = Arc::new(OnceLock::new());

    rt.spawn({
        let ih = interfaces_hook.clone();

        async move {
            let fut = async {
                // creating AsyncTun must be in the tokio runtime
                let tun = crate::tun::create(tun_fd).context("failed to create tun")?;
                node::start(c, tun, ih).await
            };
    
            if let Err(e) = fut.await {
                error!("{:?}", e);
            }
        }
    });

    let h = Handle {
        _rt: rt,
        if_to_fubuki_tx: None,
        interfaces: interfaces_hook
    };
    Ok(h)
}

#[repr(C)]
pub struct FubukiStartOptions {
    ctx: *mut c_void,
    node_config_json: *const c_char,
    device_index: u32,
    fubuki_to_if_fn: FubukiToIfFn,
    add_addr_fn: AddAddrFn,
    delete_addr_fn: DeleteAddrFn,
    tun_fd: i32
}

#[no_mangle]
pub extern "C" fn fubuki_start(
    opts: *const FubukiStartOptions,
    version: u32,
    error: *mut c_char,
) -> *mut Handle {
    let options = unsafe { &*opts };

    let res = match version {
        FUBUKI_START_OPTIONS_VERSION1 => {
            fubuki_init_inner(
                options.node_config_json,
                options.ctx,
                options.fubuki_to_if_fn,
                options.add_addr_fn,
                options.delete_addr_fn,
                options.device_index,
            )
        }
        #[cfg(target_os = "android")]
        FUBUKI_START_OPTIONS_VERSION2 => {
            fubuki_init_with_tun(
                options.node_config_json,
                options.tun_fd as std::os::fd::RawFd
            )
        }
        _ => {
            Err(anyhow!(
                "unknown version {}",
                version
            ))
        }
    };

    match res {
        Ok(p) => Box::into_raw(Box::new(p)),
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

#[no_mangle]
pub extern "C" fn fubuki_version() -> *const c_char {
    const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), '\0');
    VERSION.as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn interfaces_info(handle: *const Handle, info_json: *mut c_char) {
    let handle = unsafe { &*handle };
    generic_interfaces_info(&handle.interfaces, info_json)
}