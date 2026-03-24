use std::mem::size_of;
use std::ops::Range;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use arc_swap::{ArcSwap, Cache};
use rand::{Rng, SeedableRng};
use tokio::time::Instant;

use crate::common::allocator;
use crate::common::hook::{Hooks, PacketRecvOutput};
use crate::common::net::protocol::{
    NetProtocol, TcpMsg, UdpMsg, UdpSocketErr, VirtualAddr, TCP_MSG_HEADER_LEN, UDP_MSG_HEADER_LEN,
};
use crate::common::net::{get_ip_dst_addr, get_ip_src_addr, UdpStatus};
#[cfg(feature = "cross-nat")]
use crate::routing_table::ItemKind;
use crate::routing_table::RoutingTable;
use crate::tun::TunDevice;
use crate::Cipher;

#[cfg(feature = "cross-nat")]
use super::routing::find_once;
use super::routing::{find_next_hop, find_route, NextHop, TransferType};
use super::types::{
    Direction, ExtendedNode, Interface, NodeList, NodeListOps, RoutingTableEnum,
    RoutingTableRefEnum,
};

async fn send<K: Cipher>(
    nonce: u16,
    inter: &Interface<K>,
    dst_node: &ExtendedNode,
    buff: &mut [u8],
    packet_range: Range<usize>,
    node_relay: bool,
    next_route_cache: &mut Vec<(VirtualAddr, Option<NextHop>, Instant)>,
    node_list: &NodeList,
) -> Result<()> {
    let mode = inter
        .specify_mode
        .get(&dst_node.node.virtual_addr)
        .unwrap_or(&inter.mode);

    macro_rules! relay_packet_through_node {
        ($max_cost: expr) => {
            if node_relay {
                if let Some(peers_map) = &inter.peers_map {
                    let next = find_next_hop(
                        inter.addr.load(),
                        dst_node.node.virtual_addr,
                        next_route_cache,
                        peers_map,
                    );

                    if let Some(next) = next {
                        if next.next != dst_node.node.virtual_addr && next.cost < $max_cost {
                            if let Some(node) = node_list.get_node(&next.next) {
                                if let UdpStatus::Available { dst_addr } = node.udp_status.load() {
                                    let socket = match &inter.udp_socket {
                                        None => unreachable!(),
                                        Some(socket) => socket,
                                    };

                                    let packet = &mut buff[packet_range.start
                                        - size_of::<VirtualAddr>()
                                        - UDP_MSG_HEADER_LEN..packet_range.end];
                                    UdpMsg::relay_encode(
                                        &inter.key,
                                        nonce,
                                        dst_node.node.virtual_addr,
                                        packet_range.len(),
                                        packet,
                                    );

                                    match UdpMsg::send_msg(socket, packet, dst_addr).await {
                                        Ok(_) => return Ok(()),
                                        Err(UdpSocketErr::FatalError(e)) => {
                                            return Err(anyhow!(
                                                "failed to send UDP packet to node {}: {}",
                                                dst_node.node.name,
                                                e
                                            ));
                                        }
                                        Err(UdpSocketErr::SuppressError(e)) => {
                                            warn!(
                                                "Failed to send UDP packet from node {}: {}",
                                                inter.node_name, e
                                            );
                                        }
                                    };
                                }
                            }
                        }
                    }
                }
            }
        };
    }

    let support_p2p = (!mode.p2p.is_empty()) && (!dst_node.node.mode.p2p.is_empty());

    if support_p2p {
        relay_packet_through_node!(200);

        let udp_status = dst_node.udp_status.load();

        if let UdpStatus::Available { dst_addr } = udp_status {
            debug!(
                "PacketSender: udp message p2p to node {}",
                dst_node.node.name
            );

            let socket = match &inter.udp_socket {
                None => unreachable!(),
                Some(socket) => socket,
            };

            let packet = &mut buff[packet_range.start - UDP_MSG_HEADER_LEN..packet_range.end];
            UdpMsg::data_encode(&inter.key, nonce, packet_range.len(), packet);

            match UdpMsg::send_msg(socket, packet, dst_addr).await {
                Ok(_) => return Ok(()),
                Err(UdpSocketErr::FatalError(e)) => {
                    return Err(anyhow!(
                        "failed to send UDP P2P packet to node {}: {}",
                        dst_node.node.name,
                        e
                    ));
                }
                Err(UdpSocketErr::SuppressError(e)) => {
                    warn!(
                        "Failed to send UDP packet from node {}: {}",
                        inter.node_name, e
                    );
                }
            };
        }

        relay_packet_through_node!(300);
    }

    if (!mode.relay.is_empty()) && (!dst_node.node.mode.relay.is_empty()) {
        for np in &mode.relay {
            match np {
                NetProtocol::TCP if inter.server_allow_tcp_relay.load(Ordering::Relaxed) => {
                    let tx = match inter.tcp_handler_channel {
                        None => unreachable!(),
                        Some(ref v) => v,
                    };

                    const DATA_START: usize = TCP_MSG_HEADER_LEN + size_of::<VirtualAddr>();
                    let mut packet = allocator::alloc(DATA_START + packet_range.len());
                    packet[DATA_START..]
                        .copy_from_slice(&buff[packet_range.start..packet_range.end]);

                    TcpMsg::relay_encode(
                        &inter.key,
                        nonce,
                        dst_node.node.virtual_addr,
                        packet_range.len(),
                        &mut packet,
                    );

                    match tx.try_send(packet) {
                        Ok(_) => {
                            debug!(
                                "PacketSender: tcp message relay to node {}",
                                dst_node.node.name
                            );
                            return Ok(());
                        }
                        Err(e) => error!("PacketSender: Failed to send packet to TCP channel: {}", e),
                    }
                }
                NetProtocol::UDP if inter.server_allow_udp_relay.load(Ordering::Relaxed) => {
                    let socket = match &inter.udp_socket {
                        None => unreachable!(),
                        Some(socket) => socket,
                    };

                    let dst_addr = match inter.server_udp_status.load() {
                        UdpStatus::Available { dst_addr } => dst_addr,
                        UdpStatus::Unavailable => continue,
                    };

                    debug!(
                        "PacketSender: udp message relay to node {}",
                        dst_node.node.name
                    );

                    let packet = &mut buff[packet_range.start
                        - size_of::<VirtualAddr>()
                        - UDP_MSG_HEADER_LEN..packet_range.end];

                    UdpMsg::relay_encode(
                        &inter.key,
                        nonce,
                        dst_node.node.virtual_addr,
                        packet_range.len(),
                        packet,
                    );

                    match UdpMsg::send_msg(socket, packet, dst_addr).await {
                        Ok(_) => return Ok(()),
                        Err(UdpSocketErr::FatalError(e)) => {
                            return Err(anyhow!(
                                "failed to send UDP relay packet to node {}: {}",
                                dst_node.node.name,
                                e
                            ));
                        }
                        Err(UdpSocketErr::SuppressError(e)) => {
                            warn!(
                                "Failed to send UDP packet from node {}: {}",
                                inter.node_name, e
                            );
                        }
                    };
                }
                _ => (),
            };
        }
    }

    if support_p2p {
        relay_packet_through_node!(500);
    }

    warn!(
        "No available route to destination node '{}', packet dropped.",
        dst_node.node.name
    );
    Ok(())
}

pub(crate) struct PacketSender<'a, InterRT, ExternRT, Tun, K> {
    rt_ref: RoutingTableRefEnum<'a, InterRT, ExternRT>,
    interfaces: &'a [&'a Interface<K>],
    nodes_cache: Vec<Cache<&'a ArcSwap<NodeList>, Arc<NodeList>>>,
    tun: &'a Tun,
    hooks: Option<&'a Hooks<K>>,
    #[cfg(feature = "cross-nat")]
    snat: Option<&'a crate::node::cross_nat::SNat>,
    rng: rand::rngs::SmallRng,
    // if_index -> (dst addr, next hop, update time)
    next_route: Vec<Vec<(VirtualAddr, Option<NextHop>, Instant)>>,
}

impl<'a, InterRT, ExternRT, Tun, K> PacketSender<'a, InterRT, ExternRT, Tun, K>
where
    InterRT: RoutingTable,
    ExternRT: RoutingTable,
    Tun: TunDevice,
    K: Cipher,
{
    pub(crate) fn new(
        rt: &'a RoutingTableEnum<InterRT, ExternRT>,
        interfaces: &'a [&'a Interface<K>],
        tun: &'a Tun,
        hooks: Option<&'a Hooks<K>>,
        #[cfg(feature = "cross-nat")] snat: Option<&'a crate::node::cross_nat::SNat>,
    ) -> Self {
        PacketSender {
            rt_ref: RoutingTableRefEnum::from(rt),
            interfaces,
            nodes_cache: interfaces
                .iter()
                .map(|v| Cache::new(&v.node_list))
                .collect::<Vec<_>>(),
            tun,
            hooks,
            #[cfg(feature = "cross-nat")]
            snat,
            rng: rand::rngs::SmallRng::from_os_rng(),
            next_route: vec![Vec::new(); interfaces.len()],
        }
    }

    pub(crate) async fn send_packet(
        &mut self,
        direction: Direction,
        packet_range: Range<usize>,
        buff: &mut [u8],
        allow_packet_forward: bool,
        allow_packet_not_in_rules_send_to_kernel: bool,
        relay_dst_addr: Option<VirtualAddr>,
    ) -> Result<()> {
        let interfaces = self.interfaces;

        let packet = &mut buff[packet_range.clone()];

        let (Ok(src_addr), Ok(mut dst_addr)) =
            (get_ip_src_addr(packet), get_ip_dst_addr(packet))
        else {
            error!("Failed to parse packet as IPv4, dropping it.");
            return Ok(());
        };

        if let Some(hooks) = self.hooks {
            let output = hooks.packet_recv(direction, packet);

            if output == PacketRecvOutput::Drop {
                return Ok(());
            }
        }

        #[cfg(feature = "cross-nat")]
        if let Some(snat) = self.snat {
            let item = match &mut self.rt_ref {
                RoutingTableRefEnum::Cache(v) => find_once(&**v.load(), src_addr, dst_addr),
                RoutingTableRefEnum::Ref(v) => unsafe { find_once(&*v.get(), src_addr, dst_addr) },
            };

            if item.and_then(|i| i.extend.item_kind) == Some(ItemKind::AllowedIpsRoute) {
                return snat.input(&buff[packet_range]).await;
            }
        }

        macro_rules! find_route_with_dst {
            ($dst_addr: expr) => {
                match &mut self.rt_ref {
                    RoutingTableRefEnum::Cache(v) => find_route(&**v.load(), src_addr, $dst_addr),
                    RoutingTableRefEnum::Ref(v) => unsafe {
                        find_route(&*v.get(), src_addr, $dst_addr)
                    },
                }
            };
        }

        let mut opt = find_route_with_dst!(dst_addr);

        if opt.is_none() {
            if let Some(relay_dst_addr) = relay_dst_addr {
                dst_addr = relay_dst_addr;
                opt = find_route_with_dst!(dst_addr);
            }
        }

        let (dst_addr, item) = match opt {
            None => {
                if direction == Direction::Input && allow_packet_not_in_rules_send_to_kernel {
                    self.tun
                        .send_packet(&buff[packet_range])
                        .await
                        .context("error send packet to tun")?;
                }

                debug!(
                    "PacketSender: cannot find route {}->{}",
                    src_addr, dst_addr
                );
                return Ok(());
            }
            Some(v) => v,
        };

        let if_index = item.interface_index;

        let (interface, node_list, next_route_cache) =
            match interfaces.iter().position(|i| i.index == if_index) {
                Some(i) => (
                    interfaces[i],
                    &**self.nodes_cache[i].load(),
                    &mut self.next_route[i],
                ),
                None => return Ok(()),
            };

        let interface_addr = interface.addr.load();
        let interface_cidr = interface.cidr.load();

        if !interface
            .server_is_connected
            .load(Ordering::Relaxed)
        {
            return Ok(());
        }

        let transfer_type = if dst_addr.is_broadcast() {
            if direction == Direction::Output && interface_addr != src_addr {
                return Ok(());
            }

            if direction == Direction::Input && !interface_cidr.contains(&src_addr) {
                return Ok(());
            }

            TransferType::Broadcast
        } else if interface_cidr.broadcast() == dst_addr {
            TransferType::Broadcast
        } else {
            TransferType::Unicast(dst_addr)
        };

        match transfer_type {
            TransferType::Unicast(addr) => {
                debug!(
                    "PacketSender: packet {}->{}; gateway: {}",
                    src_addr, dst_addr, addr
                );

                if interface_addr == addr {
                    return self
                        .tun
                        .send_packet(&buff[packet_range])
                        .await
                        .context("error send packet to tun");
                }

                let f = match direction {
                    Direction::Output => true,
                    Direction::Input if allow_packet_forward => true,
                    _ => false,
                };

                if f {
                    match node_list.get_node(&addr) {
                        None => warn!(
                            "Unable to find node for virtual address '{}', packet dropped.",
                            addr
                        ),
                        Some(node) => {
                            send(
                                self.rng.random(),
                                interface,
                                node,
                                buff,
                                packet_range,
                                true,
                                next_route_cache,
                                node_list,
                            )
                            .await?
                        }
                    };
                }
            }
            TransferType::Broadcast => {
                debug!(
                    "PacketSender: packet {}->{}; broadcast",
                    src_addr, dst_addr
                );

                match direction {
                    Direction::Output => {
                        for node in node_list {
                            if node.node.virtual_addr == interface_addr {
                                continue;
                            }

                            send(
                                self.rng.random(),
                                interface,
                                node,
                                buff,
                                packet_range.clone(),
                                false,
                                next_route_cache,
                                node_list,
                            )
                            .await?;
                        }
                    }
                    Direction::Input => {
                        self.tun
                            .send_packet(&buff[packet_range])
                            .await
                            .context("error send packet to tun")?;
                    }
                }
            }
        }
        Ok(())
    }
}
