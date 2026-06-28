use std::borrow::Cow;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use ahash::HashMap;
use parking_lot::RwLock;
use tokio::time::Instant;

use crate::common::net::protocol::{PeerStatus, VirtualAddr};
use crate::routing_table::{Item, RoutingTable};

pub(crate) async fn lookup_host(dst: &str) -> Option<SocketAddr> {
    tokio::net::lookup_host(dst).await.ok()?.next()
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct NextHop {
    pub(crate) next: VirtualAddr,
    pub(crate) cost: u64,
}

pub(crate) fn find_next_hop(
    curr: VirtualAddr,
    dst: VirtualAddr,
    cache: &mut Vec<(VirtualAddr, Option<NextHop>, Instant)>,
    peers: &RwLock<HashMap<VirtualAddr, Vec<PeerStatus>>>,
) -> Option<NextHop> {
    fn find(
        curr: VirtualAddr,
        dst: VirtualAddr,
        peers: &HashMap<VirtualAddr, Vec<PeerStatus>>,
    ) -> Option<NextHop> {
        use pathfinding::prelude::dijkstra;
        const EMPTY: &'static Vec<PeerStatus> = &Vec::new();

        let route = dijkstra(
            &curr,
            |ip| {
                let peers_status_list = peers.get(ip).unwrap_or(EMPTY);
                let mut peers = Vec::with_capacity(peers_status_list.len());

                for peer_status in peers_status_list {
                    if let (Some(latency), Some(packet_loss)) =
                        (peer_status.latency, peer_status.packet_loss)
                    {
                        // normalization
                        // 200 ms
                        let latency_quality = (latency.as_millis() as u64 * 100) / 200;
                        // 3% packet loss
                        let packet_loss_quality = (packet_loss as u64 * 100) / 3;
                        peers.push((peer_status.addr, latency_quality + packet_loss_quality));
                    }
                }
                peers
            },
            |&ip| ip == dst,
        );

        match route {
            Some((route, cost)) => {
                debug!("select route {:?} for dest addr {}, cost: {}", route, dst, cost);
                // routing sequence starts from the current address, index 1 is the next hop.
                Some(NextHop {
                    next: route[1],
                    cost,
                })
            }
            None => None,
        }
    }

    match cache.binary_search_by_key(&dst, |(addr, _, _)| *addr) {
        Ok(i) => {
            let (_, next_hop, update_time) = &cache[i];

            if update_time.elapsed() < Duration::from_secs(60) {
                return *next_hop;
            }

            let new = find(curr, dst, &peers.read());
            let (_, old, t) = &mut cache[i];
            *old = new;
            *t = Instant::now();
            new
        }
        Err(i) => {
            let next = find(curr, dst, &peers.read());
            cache.insert(i, (dst, next, Instant::now()));
            next
        }
    }
}

pub(crate) enum TransferType {
    Unicast(VirtualAddr),
    Broadcast,
}

#[allow(unused)]
pub(crate) fn find_once<RT: RoutingTable>(
    rt: &RT,
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
) -> Option<Cow<'_, Item>> {
    rt.find(src_addr, dst_addr)
}

pub(crate) fn find_route<RT: RoutingTable>(
    rt: &RT,
    src_addr: Ipv4Addr,
    mut dst_addr: Ipv4Addr,
) -> Option<(Ipv4Addr, Cow<'_, Item>)> {
    let mut item = rt.find(src_addr, dst_addr)?;
    let mut count = 1;

    // is route on link
    while item.gateway != Ipv4Addr::UNSPECIFIED {
        // too many hops, possibly loop routing
        if count > 5 {
            return None;
        }

        dst_addr = item.gateway;
        item = rt.find(src_addr, dst_addr)?;

        count += 1;
    }
    Some((dst_addr, item))
}
