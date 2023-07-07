use std::net::Ipv4Addr;
use ipnet::Ipv4Net;

pub use implements::create;

#[cfg_attr(not(feature = "hash-routing-table"), path = "array.rs")]
#[cfg_attr(feature = "hash-routing-table", path = "hash.rs")]
mod implements;

#[derive(Clone)]
pub struct Item {
    pub cidr: Ipv4Net,
    pub gateway: Ipv4Addr,
    pub interface_index: usize
}

pub trait RoutingTable {
    fn add(&mut self, item: Item);

    fn remove(&mut self, cidr: &Ipv4Net) -> Option<Item>;

    fn find(&self, addr: Ipv4Addr) -> Option<&Item>;
}