use std::borrow::Cow;
use std::net::Ipv4Addr;
use ipnet::Ipv4Net;

#[cfg_attr(not(feature = "hash-routing-table"), path = "array.rs")]
#[cfg_attr(feature = "hash-routing-table", path = "hash.rs")]
pub mod internal;
pub mod external;

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum ItemKind {
    VirtualRange,
    IpsRoute,
    AllowedIpsRoute
}

#[derive(Clone, Default)]
pub struct Extend {
    pub item_kind: Option<ItemKind>
}

#[derive(Clone)]
pub struct Item {
    pub cidr: Ipv4Net,
    pub gateway: Ipv4Addr,
    pub interface_index: usize,
    pub extend: Extend
}

pub trait RoutingTable {
    fn add(&mut self, item: Item);

    fn remove(&mut self, cidr: &Ipv4Net) -> Option<Item>;

    fn find(&self, src: Ipv4Addr, to: Ipv4Addr) -> Option<Cow<Item>>;
}