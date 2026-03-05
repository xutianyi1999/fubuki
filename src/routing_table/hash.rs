use std::borrow::Cow;
use std::net::Ipv4Addr;

use ahash::HashMap;
use ipnet::Ipv4Net;

use crate::routing_table::{Item, RoutingTable};

/// Bit N is set when at least one entry with prefix_len == N exists.
/// Allows `find` to skip prefix lengths that have no entries at all,
/// reducing worst-case hash lookups from 33 to the number of distinct
/// prefix lengths actually present in the table.
#[derive(Clone, Default)]
pub struct HashRoutingTable {
    cidrs: HashMap<Ipv4Net, Item>,
    prefix_mask: u64,
}

impl HashRoutingTable {
    #[inline]
    fn set_prefix_bit(&mut self, len: u8) {
        self.prefix_mask |= 1u64 << len;
    }

    /// Clear bit N only when no more entries with that prefix length remain.
    #[inline]
    fn clear_prefix_bit_if_empty(&mut self, len: u8) {
        let still_present = self.cidrs.keys().any(|k| k.prefix_len() == len);
        if !still_present {
            self.prefix_mask &= !(1u64 << len);
        }
    }
}

impl RoutingTable for HashRoutingTable {
    fn add(&mut self, item: Item) {
        let mut item = item;
        item.cidr = item.cidr.trunc();
        self.set_prefix_bit(item.cidr.prefix_len());
        self.cidrs.insert(item.cidr, item);
    }

    fn remove(&mut self, cidr: &Ipv4Net) -> Option<Item> {
        let cidr = &cidr.trunc();
        let removed = self.cidrs.remove(cidr);
        if removed.is_some() {
            self.clear_prefix_bit_if_empty(cidr.prefix_len());
        }
        removed
    }

    fn find(&self, _src: Ipv4Addr, to: Ipv4Addr) -> Option<Cow<Item>> {
        // Iterate only over prefix lengths that actually have entries,
        // from most specific (/32) to least specific (/0).
        let mut mask = self.prefix_mask;
        while mask != 0 {
            // highest set bit = longest (most specific) prefix remaining
            let len = 63 - mask.leading_zeros();
            mask &= !(1u64 << len); // clear this bit before the lookup
            let cidr = Ipv4Net::new(to, len as u8).unwrap().trunc();
            if let Some(item) = self.cidrs.get(&cidr) {
                return Some(Cow::Borrowed(item));
            }
        }
        None
    }
}

pub fn create() -> HashRoutingTable {
    HashRoutingTable::default()
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use ipnet::Ipv4Net;
    use crate::routing_table::{Extend, Item, ItemKind, RoutingTable};
    use super::HashRoutingTable;

    fn make_item(cidr: &str, gateway: &str, index: usize) -> Item {
        Item {
            cidr: Ipv4Net::from_str(cidr).unwrap(),
            gateway: Ipv4Addr::from_str(gateway).unwrap(),
            interface_index: index,
            extend: Extend { item_kind: Some(ItemKind::IpsRoute) },
        }
    }

    fn ip(s: &str) -> Ipv4Addr {
        Ipv4Addr::from_str(s).unwrap()
    }

    // ── prefix_mask bookkeeping ──────────────────────────────────────────

    #[test]
    fn prefix_mask_set_on_add() {
        let mut rt = HashRoutingTable::default();
        rt.add(make_item("10.0.0.0/8", "1.1.1.1", 0));
        rt.add(make_item("192.168.1.0/24", "1.1.1.1", 0));
        assert_ne!(rt.prefix_mask & (1u64 << 8),  0, "/8 bit should be set");
        assert_ne!(rt.prefix_mask & (1u64 << 24), 0, "/24 bit should be set");
        assert_eq!(rt.prefix_mask & (1u64 << 16), 0, "/16 bit should be clear");
    }

    #[test]
    fn prefix_mask_cleared_after_last_remove() {
        let mut rt = HashRoutingTable::default();
        rt.add(make_item("10.0.0.0/8", "1.1.1.1", 0));
        let cidr = Ipv4Net::from_str("10.0.0.0/8").unwrap();
        rt.remove(&cidr);
        assert_eq!(rt.prefix_mask & (1u64 << 8), 0, "/8 bit should be cleared after removal");
    }

    #[test]
    fn prefix_mask_kept_when_sibling_remains() {
        let mut rt = HashRoutingTable::default();
        rt.add(make_item("10.0.0.0/8",  "1.1.1.1", 0));
        rt.add(make_item("11.0.0.0/8",  "1.1.1.1", 1));
        rt.remove(&Ipv4Net::from_str("10.0.0.0/8").unwrap());
        assert_ne!(rt.prefix_mask & (1u64 << 8), 0, "/8 bit should remain while 11.0.0.0/8 exists");
    }

    // ── find: longest-prefix-match ───────────────────────────────────────

    #[test]
    fn find_exact_host_route() {
        let mut rt = HashRoutingTable::default();
        rt.add(make_item("1.2.3.4/32", "10.0.0.1", 0));
        let item = rt.find(Ipv4Addr::UNSPECIFIED, ip("1.2.3.4"));
        assert!(item.is_some());
        assert_eq!(item.unwrap().interface_index, 0);
    }

    #[test]
    fn find_returns_most_specific() {
        let mut rt = HashRoutingTable::default();
        rt.add(make_item("0.0.0.0/0",      "1.0.0.1", 0));
        rt.add(make_item("10.0.0.0/8",     "1.0.0.2", 1));
        rt.add(make_item("10.1.0.0/16",    "1.0.0.3", 2));
        rt.add(make_item("10.1.2.0/24",    "1.0.0.4", 3));

        // Should match /24
        let item = rt.find(Ipv4Addr::UNSPECIFIED, ip("10.1.2.5"));
        assert_eq!(item.unwrap().interface_index, 3, "expected /24 match");

        // Should match /16 (no /24 for 10.1.3.x)
        let item = rt.find(Ipv4Addr::UNSPECIFIED, ip("10.1.3.1"));
        assert_eq!(item.unwrap().interface_index, 2, "expected /16 match");

        // Should match /8 (no /16 for 10.2.x.x)
        let item = rt.find(Ipv4Addr::UNSPECIFIED, ip("10.2.0.1"));
        assert_eq!(item.unwrap().interface_index, 1, "expected /8 match");

        // Should match /0 (default route)
        let item = rt.find(Ipv4Addr::UNSPECIFIED, ip("8.8.8.8"));
        assert_eq!(item.unwrap().interface_index, 0, "expected /0 default route");
    }

    #[test]
    fn find_no_match_returns_none() {
        let mut rt = HashRoutingTable::default();
        rt.add(make_item("10.0.0.0/8", "1.1.1.1", 0));
        assert!(rt.find(Ipv4Addr::UNSPECIFIED, ip("192.168.1.1")).is_none());
    }

    #[test]
    fn find_default_route_matches_everything() {
        let mut rt = HashRoutingTable::default();
        rt.add(make_item("0.0.0.0/0", "1.1.1.1", 0));
        assert!(rt.find(Ipv4Addr::UNSPECIFIED, ip("1.2.3.4")).is_some());
        assert!(rt.find(Ipv4Addr::UNSPECIFIED, ip("255.255.255.255")).is_some());
    }

    // ── remove ──────────────────────────────────────────────────────────

    #[test]
    fn remove_nonexistent_returns_none() {
        let mut rt = HashRoutingTable::default();
        let cidr = Ipv4Net::from_str("10.0.0.0/8").unwrap();
        assert!(rt.remove(&cidr).is_none());
    }

    #[test]
    fn remove_then_find_misses() {
        let mut rt = HashRoutingTable::default();
        rt.add(make_item("10.0.0.0/8", "1.1.1.1", 0));
        rt.remove(&Ipv4Net::from_str("10.0.0.0/8").unwrap());
        assert!(rt.find(Ipv4Addr::UNSPECIFIED, ip("10.1.2.3")).is_none());
    }

    // ── add overwrites ───────────────────────────────────────────────────

    #[test]
    fn add_overwrites_existing_cidr() {
        let mut rt = HashRoutingTable::default();
        rt.add(make_item("10.0.0.0/8", "1.1.1.1", 0));
        rt.add(make_item("10.0.0.0/8", "1.1.1.1", 99));
        let item = rt.find(Ipv4Addr::UNSPECIFIED, ip("10.1.2.3")).unwrap();
        assert_eq!(item.interface_index, 99);
    }

    // ── CIDR normalization (host bits set) ───────────────────────────────

    #[test]
    fn add_with_host_bits_still_findable() {
        // "10.5.3.1/8" has host bits set; should be normalized to "10.0.0.0/8"
        let mut rt = HashRoutingTable::default();
        rt.add(make_item("10.5.3.1/8", "1.1.1.1", 7));
        let item = rt.find(Ipv4Addr::UNSPECIFIED, ip("10.9.9.9"));
        assert!(item.is_some(), "should match 10.0.0.0/8 after normalization");
        assert_eq!(item.unwrap().interface_index, 7);
    }
}