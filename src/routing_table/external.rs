use std::borrow::Cow;
use std::ffi::c_void;
use std::mem::{transmute, MaybeUninit};
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use ipnet::Ipv4Net;
use libloading::{Library, Symbol};

use crate::routing_table::{Item, ItemKind, RoutingTable};
use crate::{node, Context, ExternalContext};

#[repr(C)]
#[derive(Copy, Clone)]
struct CidrC {
    addr: u32,
    prefix_len: u8,
}

impl From<CidrC> for Ipv4Net {
    fn from(value: CidrC) -> Self {
        Ipv4Net::new(Ipv4Addr::from(value.addr), value.prefix_len).unwrap()
    }
}

impl From<Ipv4Net> for CidrC {
    fn from(value: Ipv4Net) -> Self {
        CidrC {
            addr: u32::from(value.addr()),
            prefix_len: value.prefix_len(),
        }
    }
}

#[repr(C)]
struct OptionC<T> {
    is_some: bool,
    value: MaybeUninit<T>,
}

impl<T: Copy> Clone for OptionC<T> {
    fn clone(&self) -> Self {
        OptionC {
            is_some: self.is_some,
            value: self.value,
        }
    }
}

impl<T> From<OptionC<T>> for Option<T> {
    fn from(value: OptionC<T>) -> Self {
        if value.is_some {
            Some(unsafe { value.value.assume_init() })
        } else {
            None
        }
    }
}

impl<T> From<Option<T>> for OptionC<T> {
    fn from(value: Option<T>) -> Self {
        match value {
            None => OptionC {
                is_some: false,
                value: MaybeUninit::uninit(),
            },
            Some(v) => OptionC {
                is_some: true,
                value: MaybeUninit::new(v),
            },
        }
    }
}

#[repr(C)]
#[derive(Clone)]
struct ExtendC {
    item_kind: OptionC<ItemKind>,
}

impl From<ExtendC> for super::Extend {
    fn from(value: ExtendC) -> Self {
        super::Extend {
            item_kind: Option::from(value.item_kind),
        }
    }
}

impl From<super::Extend> for ExtendC {
    fn from(value: crate::routing_table::Extend) -> Self {
        ExtendC {
            item_kind: OptionC::from(value.item_kind),
        }
    }
}

#[repr(C)]
#[derive(Clone)]
struct ItemC {
    cidr: CidrC,
    gateway: u32,
    interface_index: usize,
    extend: ExtendC,
}

impl From<ItemC> for Item {
    fn from(value: ItemC) -> Self {
        Item {
            cidr: Ipv4Net::from(value.cidr),
            gateway: Ipv4Addr::from(value.gateway),
            interface_index: value.interface_index,
            extend: super::Extend::from(value.extend),
        }
    }
}

impl From<Item> for ItemC {
    fn from(value: Item) -> Self {
        ItemC {
            cidr: CidrC::from(value.cidr),
            gateway: u32::from(value.gateway),
            interface_index: value.interface_index,
            extend: ExtendC::from(value.extend),
        }
    }
}

type AddFn = extern "C" fn(handle: *mut c_void, item_c: ItemC);
type RemoveFn = extern "C" fn(handle: *mut c_void, cidr: *const CidrC) -> OptionC<ItemC>;
type FindFn = extern "C" fn(handle: *mut c_void, src: u32, to: u32) -> OptionC<ItemC>;
type CreateFn = extern "C" fn(ctx: ExternalContext) -> *mut c_void;
type DropFn = extern "C" fn(*mut c_void);

// self reference
pub struct ExternalRoutingTable<K> {
    handle: *mut c_void,
    _ctx: Arc<Context<K>>,
    _lib: Library,
    add_fn: Symbol<'static, AddFn>,
    remove_fn: Symbol<'static, RemoveFn>,
    find_fn: Symbol<'static, FindFn>,
    drop_fn: Symbol<'static, DropFn>,
}

unsafe impl<K: Send> Send for ExternalRoutingTable<K> {}

unsafe impl<K: Sync> Sync for ExternalRoutingTable<K> {}

impl<K> RoutingTable for ExternalRoutingTable<K> {
    fn add(&mut self, item: Item) {
        (self.add_fn)(self.handle, ItemC::from(item))
    }

    fn remove(&mut self, cidr: &Ipv4Net) -> Option<Item> {
        let optc = (self.remove_fn)(self.handle, &CidrC::from(*cidr));
        Option::<ItemC>::from(optc).map(Item::from)
    }

    fn find(&self, src: Ipv4Addr, to: Ipv4Addr) -> Option<Cow<'_, Item>> {
        let optc = (self.find_fn)(self.handle, u32::from(src), u32::from(to));
        Option::<ItemC>::from(optc).map(|i| Cow::Owned(Item::from(i)))
    }
}

impl<K> Drop for ExternalRoutingTable<K> {
    fn drop(&mut self) {
        (self.drop_fn)(self.handle);
    }
}

pub fn create<K>(
    lib_path: &Path,
    ctx: Arc<Context<K>>
) -> Result<ExternalRoutingTable<K>> {
    let extern_ctx = ExternalContext {
        ctx: Arc::as_ptr(&ctx) as *const c_void,
        interfaces_info_fn: node::interfaces_info_query::<K> as *const c_void,
        packet_send_fn: node::packet_send::<K> as *const c_void
    };

    unsafe {
        let lib = Library::new(lib_path)?;

        let create_fn: Symbol<CreateFn> = lib.get(b"create_routing_table")?;
        let add_fn = transmute(lib.get::<AddFn>(b"add_route")?);
        let remove_fn = transmute(lib.get::<RemoveFn>(b"remove_route")?);
        let find_fn = transmute(lib.get::<FindFn>(b"find_route")?);
        let drop_fn = transmute(lib.get::<DropFn>(b"drop_routing_table")?);

        let handle = create_fn(extern_ctx);

        let rt = ExternalRoutingTable {
            handle,
            _ctx: ctx,
            _lib: lib,
            add_fn,
            remove_fn,
            find_fn,
            drop_fn,
        };
        Ok(rt)
    }
}
