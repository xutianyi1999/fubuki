use std::borrow::Cow;
use std::net::Ipv4Addr;
use ipnet::Ipv4Net;
use crate::routing_table::{Item, RoutingTable};

#[derive(Clone, Default)]
pub struct ArrayRoutingTable {
    inner: Vec<Item>,
}

impl RoutingTable for ArrayRoutingTable {
    fn add(&mut self, item: Item) {
        let index = self.inner.partition_point(|v| v.cidr.prefix_len() >= item.cidr.prefix_len());
        self.inner.insert(index, item);
    }

    fn remove(&mut self, cidr: &Ipv4Net) -> Option<Item> {
        let index = self.inner
            .iter()
            .position(|v| v.cidr == *cidr);

        index.map(|index| self.inner.remove(index))
    }

    fn find(&self, _src: Ipv4Addr, to: Ipv4Addr) -> Option<Cow<'_, Item>> {
        self.inner
            .iter()
            .find(|v| v.cidr.contains(&to))
            .map(Cow::Borrowed)
    }
}

pub fn create() -> ArrayRoutingTable {
    ArrayRoutingTable::default()
}