use std::{mem::transmute, os::raw::c_void, path::Path, sync::Arc};
use anyhow::Result;
use libloading::{Library, Symbol};

use crate::{node::{self, Direction}, Context, ExternalContext};

type Callback = extern "C" fn(handle: *mut c_void, input: *mut c_void, output: *mut c_void);

type CreateFn = extern "C" fn(ctx: ExternalContext) -> *mut c_void;
type DropFn = extern "C" fn(*mut c_void);

pub struct Hooks<K> {
    handle: *mut c_void,
    _ctx: Arc<Context<K>>,
    _lib: Library,
    drop_fn: Symbol<'static, DropFn>,
    packet_recv: Option<Symbol<'static, Callback>>
}

unsafe impl<K: Send> Send for Hooks<K> {}

unsafe impl<K: Sync> Sync for Hooks<K> {}

impl<K> Drop for Hooks<K> {
    fn drop(&mut self) {
        (self.drop_fn)(self.handle);
    }
}

pub fn open_hooks_dll<K>(
    lib_path: &Path,
    ctx: Arc<Context<K>>
) -> Result<Hooks<K>> {
    let extern_ctx = ExternalContext {
        ctx: Arc::as_ptr(&ctx) as *const c_void,
        interfaces_info_fn: node::interfaces_info_query::<K> as *const c_void,
        packet_send_fn: node::packet_send::<K> as *const c_void
    };

    unsafe {
        let lib = Library::new(lib_path)?;
        let create_fn: Symbol<CreateFn> = lib.get(b"create_hooks")?;
        let drop_fn = transmute(lib.get::<DropFn>(b"drop_hooks")?);

        let packet_recv = transmute(lib.get::<Callback>(b"packet_recv").ok());
        let handle = create_fn(extern_ctx);

        let hooks = Hooks {
            handle,
            _ctx: ctx,
            _lib: lib,
            drop_fn,
            packet_recv
        };
        Ok(hooks)
    }
    
}

#[repr(C)]
#[derive(PartialEq, Eq)]
pub enum PacketRecvOutput {
    Accept = 0,
    Drop
}

impl <K> Hooks<K> {
    pub fn packet_recv(&self, direction: Direction, packet: &mut [u8]) -> PacketRecvOutput {
        #[repr(C)]
        struct Input {
            direction: Direction,
            packet: *mut u8,
            len: usize
        }

        let mut input = Input {
            direction,
            packet: packet.as_mut_ptr(),
            len: packet.len()
        };
        let mut output = PacketRecvOutput::Accept;

        if let Some(call) = self.packet_recv.as_ref() {
            let call = **call;
            call(self.handle, (&mut input) as *mut Input as *mut c_void, (&mut output) as *mut PacketRecvOutput as *mut c_void);
        }

        output
    }
}
