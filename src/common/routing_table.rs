use ahash::{HashMap, HashMapExt};
use ipnet::Ipv4Net;
use std::net::Ipv4Addr;

// todo add array routing table

#[derive(Clone)]
pub struct Item {
    pub cidr: Ipv4Net,
    pub gateway: Ipv4Addr,
    pub interface_index: usize
}

#[derive(Clone)]
pub struct RoutingTable {
    cidrs: HashMap<Ipv4Net, Item>,
}

impl RoutingTable {
    pub fn new() -> Self {
        RoutingTable {
            cidrs: HashMap::new(),
        }
    }

    pub fn add(&mut self, cidr: Ipv4Net, gateway: Ipv4Addr, interface_index: usize) {
        let item = Item {
            cidr,
            gateway,
            interface_index
        };
        self.cidrs.insert(cidr, item);
    }

    pub fn remove(&mut self, cidr: &Ipv4Net) -> Option<Item> {
        self.cidrs.remove(cidr)
    }

    pub fn find(&self, addr: Ipv4Addr) -> Option<&Item> {
        let cidrs = &self.cidrs;

        for len in (0..=32).rev() {
            let cidr = Ipv4Net::new(addr, len).unwrap().trunc();

            if let Some(v) = cidrs.get(&cidr) {
                return Some(v)
            }
        }
        None
    }
}
