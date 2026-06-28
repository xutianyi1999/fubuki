use std::ffi::c_void;
use std::sync::{Arc, OnceLock};

use flume;

use crate::common::allocator::Bytes;
use crate::node::{Direction, Interface};

pub struct Context<K> {
    pub interfaces: Option<Arc<OnceLock<Vec<Arc<Interface<K>>>>>>,
    pub send_packet_chan: Option<flume::Sender<(Direction, Bytes)>>,
}

#[repr(C)]
pub struct ExternalContext {
    pub ctx: *const c_void,
    pub interfaces_info_fn: *const c_void,
    pub packet_send_fn: *const c_void,
}
