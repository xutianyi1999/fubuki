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

    fn find(&self, src: Ipv4Addr, to: Ipv4Addr) -> Option<Cow<'_, Item>>;
}

#[test]
fn test() {
    use std::str::FromStr;

    let mut router = internal::create();

    router.add(Item {
        cidr: Ipv4Net::from_str("0.0.0.0/0").unwrap(),
        gateway: Ipv4Addr::from_str("10.0.199.2").unwrap(),
        interface_index: 0,
        extend: Extend {
            item_kind: Some(ItemKind::IpsRoute)
        }
    });

    let src = Ipv4Addr::UNSPECIFIED;
    let dst = Ipv4Addr::from_str("1.1.1.1").unwrap();
    assert!(router.find(src, dst).is_some());
}