use std::net::Ipv4Addr;

use ahash::HashMap;
use ipnet::Ipv4Net;

use crate::routing_table::{Item, RoutingTable};

#[derive(Clone, Default)]
pub struct HashRoutingTable {
    cidrs: HashMap<Ipv4Net, Item>,
}

impl RoutingTable for HashRoutingTable {
    fn add(&mut self, item: Item) {
        self.cidrs.insert(item.cidr, item);
    }

    fn remove(&mut self, cidr: &Ipv4Net) -> Option<Item> {
        self.cidrs.remove(cidr)
    }

    fn find(&self, addr: Ipv4Addr) -> Option<&Item> {
        let cidrs = &self.cidrs;

        for len in (0..=32).rev() {
            let cidr = Ipv4Net::new(addr, len).unwrap().trunc();
            let item = cidrs.get(&cidr);

            if item.is_some() {
                return item;
            }
        }
        None
    }
}

pub fn create() -> HashRoutingTable {
    HashRoutingTable::default()
}