use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::num::NonZeroUsize;
use std::time::Instant;

use ahash::HashMap;
use ipnet::Ipv4Net;
use lru::LruCache;
use parking_lot::RwLock;

use super::msg::{DirectoryEntryWire, NeighborSyncBody, ReachEntry};

const MAX_NEIGHBORS: usize = 32;
const MAX_SYNC_ENTRIES: usize = 24;

/// One member as stored locally: overlay identity, merge version, and best-known underlay paths.
#[derive(Debug, Clone)]
pub struct Entry {
    pub display_name: String,
    /// Overlay IPv4 network for this member; the assigned host is `virtual_net.addr()`.
    pub virtual_net: Ipv4Net,
    /// Last merged directory [`super::msg::DirectoryEntryWire::version`] / HELLO row version.
    pub version: u64,
    /// Observed or announced UDP source for FBDC (preferred for encapsulation).
    pub direct_udp: Option<SocketAddrV4>,
    /// STUN XOR mapped address, used as punch target and fallback when `direct_udp` is unknown.
    pub reflexive: Option<SocketAddrV4>,
    /// Last time this row was updated from the network or locally.
    pub last_seen: Instant,
}

/// Thread-safe member directory and bounded neighbor fan-out set.
pub struct Directory {
    inner: RwLock<Inner>,
}

/// Mutable directory state behind [`Directory`].
struct Inner {
    /// Members keyed by `node_id`.
    by_id: HashMap<[u8; 16], Entry>,
    /// Bootstrap seeds and recently seen UDP sources used for gossip fan-out (LRU eviction).
    neighbors: LruCache<SocketAddr, ()>,
    /// Underlay address learned from [`NeighborSyncBody`] before a HELLO/MEMBER row exists for that `node_id`.
    reach_pending: HashMap<[u8; 16], SocketAddrV4>,
}

impl Directory {
    pub fn new() -> Self {
        Directory {
            inner: RwLock::new(Inner {
                by_id: HashMap::default(),
                neighbors: LruCache::new(
                    NonZeroUsize::new(MAX_NEIGHBORS).expect("neighbor cap must be non-zero"),
                ),
                reach_pending: HashMap::default(),
            }),
        }
    }

    pub fn add_neighbor(&self, addr: SocketAddr) {
        let mut g = self.inner.write();
        g.neighbors.put(addr, ());
    }

    pub fn neighbors_snapshot(&self) -> Vec<SocketAddr> {
        self.inner.read().neighbors.iter().map(|(a, _)| *a).collect()
    }

    pub fn seed_neighbors(&self, addrs: &[SocketAddr]) {
        let mut g = self.inner.write();
        for a in addrs {
            g.neighbors.put(*a, ());
        }
    }

    /// Merge [`NeighborSyncBody`] rows: updates `direct_udp`, may insert placeholder entries, extends neighbor LRU.
    pub fn merge_neighbor_sync(&self, body: &NeighborSyncBody, now: Instant) {
        let mut g = self.inner.write();
        for e in body.entries.iter().take(MAX_SYNC_ENTRIES) {
            let Ok(vnet) = Ipv4Net::new(Ipv4Addr::from(e.virtual_ip), e.virtual_prefix_len) else {
                continue;
            };
            let sa = SocketAddrV4::new(Ipv4Addr::from(e.ip), e.port);
            g.neighbors.put(SocketAddr::V4(sa), ());
            match g.by_id.get_mut(&e.node_id) {
                Some(ent) => {
                    ent.direct_udp = Some(sa);
                    ent.last_seen = now;
                }
                None => {
                    g.by_id.insert(
                        e.node_id,
                        Entry {
                            display_name: String::new(),
                            virtual_net: vnet,
                            version: 0,
                            direct_udp: Some(sa),
                            reflexive: None,
                            last_seen: now,
                        },
                    );
                }
            }
            g.reach_pending.remove(&e.node_id);
        }
    }

    pub fn build_neighbor_sync(&self, self_id: [u8; 16]) -> NeighborSyncBody {
        let g = self.inner.read();
        let mut entries: Vec<ReachEntry> = Vec::new();
        if let Some(ent) = g.by_id.get(&self_id) {
            if let Some(sa) = ent.direct_udp.or(ent.reflexive) {
                entries.push(ReachEntry {
                    node_id: self_id,
                    virtual_ip: ent.virtual_net.addr().octets(),
                    virtual_prefix_len: ent.virtual_net.prefix_len(),
                    ip: sa.ip().octets(),
                    port: sa.port(),
                });
            }
        }
        let mut rest: Vec<([u8; 16], Ipv4Net, SocketAddrV4)> = g
            .by_id
            .iter()
            .filter(|(id, e)| {
                **id != self_id && (e.direct_udp.is_some() || e.reflexive.is_some())
            })
            .map(|(id, e)| {
                let sa = e.direct_udp.or(e.reflexive).expect("filtered");
                (*id, e.virtual_net, sa)
            })
            .collect();
        rest.sort_by_key(|(id, _, _)| *id);
        for (nid, vnet, sa) in rest {
            if entries.len() >= MAX_SYNC_ENTRIES {
                break;
            }
            entries.push(ReachEntry {
                node_id: nid,
                virtual_ip: vnet.addr().octets(),
                virtual_prefix_len: vnet.prefix_len(),
                ip: sa.ip().octets(),
                port: sa.port(),
            });
        }
        NeighborSyncBody { entries }
    }

    pub fn punch_targets(&self, self_id: [u8; 16]) -> Vec<SocketAddrV4> {
        let g = self.inner.read();
        let mut v: Vec<SocketAddrV4> = g
            .by_id
            .iter()
            .filter(|(id, _)| **id != self_id)
            .filter_map(|(_, e)| e.reflexive)
            .collect();
        v.sort_by_key(|a| (a.ip().to_bits(), a.port()));
        v.dedup();
        v
    }

    /// After hole-punch packet, pin direct path to observed source.
    pub fn note_punch_from(&self, peer_id: [u8; 16], from: SocketAddrV4, now: Instant) {
        let mut g = self.inner.write();
        let Some(ent) = g.by_id.get_mut(&peer_id) else {
            return;
        };
        let accept = match ent.reflexive {
            None => true,
            Some(r) => r == from || r.ip() == from.ip(),
        };
        if accept {
            ent.direct_udp = Some(from);
            ent.last_seen = now;
        }
    }

    /// Merge remote row; `recv` is used when `direct_*` missing in wire.
    pub fn merge_wire(&self, w: DirectoryEntryWire, recv: SocketAddr, now: Instant) {
        let mut g = self.inner.write();
        let direct = match (w.direct_ip, w.direct_port) {
            (Some(ip), Some(port)) => Some(SocketAddrV4::new(Ipv4Addr::from(ip), port)),
            _ => match recv {
                SocketAddr::V4(a) => Some(a),
                _ => None,
            },
        };

        let conflict = g.by_id.iter().any(|(id, e)| {
            *id != w.node_id && e.virtual_net.addr() == w.virtual_net.addr()
        });
        if conflict {
            warn!(
                "dc: virtual_addr conflict {} includes {}",
                w.virtual_net.addr(),
                uuid::Uuid::from_bytes(w.node_id)
            );
        }

        let pending_rx = g.reach_pending.remove(&w.node_id);

        use std::cmp::Ordering;
        match g.by_id.get(&w.node_id).cloned() {
            None => {
                g.by_id.insert(
                    w.node_id,
                    Entry {
                        display_name: w.display_name,
                        virtual_net: w.virtual_net,
                        version: w.version,
                        direct_udp: direct,
                        reflexive: pending_rx,
                        last_seen: now,
                    },
                );
            }
            Some(cur) => match w.version.cmp(&cur.version) {
                Ordering::Greater => {
                    g.by_id.insert(
                        w.node_id,
                        Entry {
                            display_name: w.display_name,
                            virtual_net: w.virtual_net,
                            version: w.version,
                            direct_udp: direct.or(cur.direct_udp),
                            reflexive: cur.reflexive.or(pending_rx),
                            last_seen: now,
                        },
                    );
                }
                Ordering::Equal => {
                    let mut e = cur;
                    e.display_name = w.display_name;
                    e.virtual_net = w.virtual_net;
                    if let Some(d) = direct {
                        e.direct_udp = Some(d);
                    }
                    if e.reflexive.is_none() {
                        e.reflexive = pending_rx;
                    }
                    e.last_seen = now;
                    g.by_id.insert(w.node_id, e);
                }
                Ordering::Less => {}
            },
        }
    }

    pub fn upsert_self(
        &self,
        node_id: [u8; 16],
        display_name: String,
        virtual_net: Ipv4Net,
        version: u64,
        now: Instant,
    ) {
        let mut g = self.inner.write();
        g.by_id.insert(
            node_id,
            Entry {
                display_name,
                virtual_net,
                version,
                direct_udp: None,
                reflexive: None,
                last_seen: now,
            },
        );
    }

    pub fn set_self_reflexive(&self, node_id: [u8; 16], sa: SocketAddrV4, now: Instant) {
        let mut g = self.inner.write();
        if let Some(ent) = g.by_id.get_mut(&node_id) {
            ent.reflexive = Some(sa);
            ent.last_seen = now;
        }
    }

    pub fn self_reflexive(&self, self_id: [u8; 16]) -> Option<SocketAddrV4> {
        self.inner
            .read()
            .by_id
            .get(&self_id)
            .and_then(|e| e.reflexive)
    }

    pub fn lookup_udp_for_dst(&self, dst: Ipv4Addr, self_id: [u8; 16]) -> Option<SocketAddrV4> {
        let g = self.inner.read();
        for (id, e) in g.by_id.iter() {
            if *id == self_id {
                continue;
            }
            if e.virtual_net.addr() == dst {
                return e.direct_udp.or(e.reflexive);
            }
        }
        None
    }
}
