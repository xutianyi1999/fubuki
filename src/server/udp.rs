use std::mem::size_of;
use std::net::SocketAddr;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;

use ahash::{HashSet, HashSetExt};
use anyhow::{anyhow, Result};
use parking_lot::RwLock;
use rand::{Rng, SeedableRng};
use tokio::io::DuplexStream;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::sync::watch;

use crate::common::allocator;
use crate::common::allocator::Bytes;
use crate::common::cipher::Cipher;
use crate::common::net::protocol::{
    HeartbeatType, NetProtocol, Seq, TcpMsg, UdpMsg, UdpSocketErr, VirtualAddr,
    SERVER_VIRTUAL_ADDR, TCP_MSG_HEADER_LEN, UDP_BUFF_SIZE, UDP_MSG_HEADER_LEN,
};
use crate::common::net::{get_ip_dst_addr, get_ip_src_addr, PushResult, UdpStatus};
use crate::kcp_bridge::KcpStack;
use crate::GroupFinalize;

use super::types::GroupHandle;
pub(crate) async fn udp_handler<K: Cipher + Clone + Send + Sync>(
    group: &'static GroupFinalize<K>,
    socket: Arc<UdpSocket>,
    group_handle: Arc<GroupHandle>,
    heartbeat_interval: Duration,
    packet_loss_limit: u64,
    packet_continuous_recv: u64,
    notified: watch::Receiver<()>,
    kcp_acceptor_channel: mpsc::Sender<(DuplexStream, SocketAddr)>,
) -> Result<()> {
    let key = &group.key;

    let heartbeat_schedule = async {
        let group_handle = group_handle.clone();
        let socket = socket.clone();
        let mut notified = notified.clone();

        tokio::spawn(async move {
            let fut = async {
                let mut buff = [0u8; UDP_MSG_HEADER_LEN + size_of::<VirtualAddr>() + size_of::<Seq>() + size_of::<HeartbeatType>()];
                let mut rng = rand::rngs::SmallRng::from_os_rng();

                loop {
                    let mut list = Vec::new();

                    {
                        let guard = group_handle.mapping.read();

                        for node in guard.values() {
                            let wan = node.node.load().wan_udp_addr;

                            let socket_addr = match wan {
                                None => continue,
                                Some(v) => v
                            };

                            let mut heartbeat_status = node.udp_heartbeat_cache.write();
                            heartbeat_status.check();

                            if node.udp_status.load() != UdpStatus::Unavailable &&
                                heartbeat_status.packet_continuous_loss_count >= packet_loss_limit
                            {
                                node.udp_status.store(UdpStatus::Unavailable);
                            }

                            heartbeat_status.ping();
                            list.push((socket_addr, heartbeat_status.seq));
                        }
                    };

                    for (sock_addr, seq) in list {
                        let len = UdpMsg::heartbeat_encode(key, rng.random(), SERVER_VIRTUAL_ADDR, seq, HeartbeatType::Req, &mut buff);
                        let packet = &mut buff[..len];

                        match UdpMsg::send_msg(&socket, packet, sock_addr).await {
                            Ok(_) => (),
                            Err(UdpSocketErr::FatalError(e)) => return Result::<(), _>::Err(anyhow!("UDP heartbeat sender for group '{}' encountered a fatal socket error: {}", group.name, e)),
                            Err(UdpSocketErr::SuppressError(e)) => {
                                warn!("Failed to send UDP packet for group {}: {}", group.name, e);
                            }
                        };
                    }

                    tokio::time::sleep(heartbeat_interval).await;
                }
            };

            tokio::select! {
                res = fut => res,
                _ = notified.changed() => Err(anyhow!("UDP heartbeat sender for group '{}' aborted due to notification.", group.name))
            }
        }).await?
    };

    let recv_handler = async {
        let group_handle = group_handle.clone();
        let socket = socket.clone();
        let mut notified = notified.clone();
        let kcp_acceptor_channel = kcp_acceptor_channel.clone();

        tokio::spawn(async move {
            let fut = async {
                let mut buff = vec![0u8; UDP_BUFF_SIZE];
                let mut rng = rand::rngs::SmallRng::from_os_rng();
                let kcp_sessions = Arc::new(RwLock::new(Vec::<(u32, mpsc::Sender<Bytes>)>::new()));
                let kcp_sessions_expired_list = Arc::new(RwLock::new(HashSet::new()));

                loop {
                    let (len, peer_addr) = match UdpMsg::recv_msg(socket.deref(), &mut buff).await {
                        Ok(v) => v,
                        Err(e) => {
                            error!("Failed to process UDP message for group {}: {:?}", group.name, e.as_ref());
                            continue;
                        }
                    };

                    let packet = &mut buff[..len];

                    let msg = match UdpMsg::decode(key, packet) {
                        Ok(msg) => msg,
                        Err(e) => {
                            error!("Failed to process UDP message for group {}: {:?}", group.name, e);
                            continue;
                        }
                    };

                    match msg {
                        UdpMsg::Heartbeat(dst_virt_addr, seq, HeartbeatType::Req) => {
                            let mut is_known = false;

                            {
                                let guard = group_handle.mapping.read();

                                if let Some(handle) = guard.get(&dst_virt_addr) {
                                    is_known = true;
                                    let node = handle.node.load();

                                    if node.wan_udp_addr != Some(peer_addr) {
                                        let mut new_node = (**node).clone();
                                        drop(node);

                                        new_node.wan_udp_addr = Some(peer_addr);
                                        handle.node.store(Arc::new(new_node));
                                        group_handle.sync(&guard)?;
                                    }
                                }
                            };

                            if is_known {
                                let len = UdpMsg::heartbeat_encode(key, rng.random(), SERVER_VIRTUAL_ADDR, seq, HeartbeatType::Resp, &mut buff);
                                let packet = &mut buff[..len];

                                match UdpMsg::send_msg(&socket, packet, peer_addr).await {
                                    Ok(_) => (),
                                    Err(UdpSocketErr::FatalError(e)) => return Err(anyhow!("UDP heartbeat responder for group '{}' encountered a fatal socket error while sending response: {}", group.name, e)),
                                    Err(UdpSocketErr::SuppressError(e)) => {
                                        warn!("Failed to send UDP packet for group {}: {}", group.name, e);
                                    }
                                };
                            }
                        }
                        UdpMsg::Heartbeat(dst_virt_addr, seq, HeartbeatType::Resp) => {
                            let guard = group_handle.mapping.read();

                            if let Some(node) = guard.get(&dst_virt_addr) {
                                let mut udp_heartbeat_cache = node.udp_heartbeat_cache.write();

                                if udp_heartbeat_cache.reply(seq).is_none() {
                                    continue;
                                }

                                if node.udp_status.load() == UdpStatus::Unavailable &&
                                    udp_heartbeat_cache.packet_continuous_recv_count >= packet_continuous_recv
                                {
                                    node.udp_status.store(UdpStatus::Available {dst_addr: peer_addr});
                                }
                            }
                        }
                        UdpMsg::Relay(dst_virt_addr, data) => {
                            if !group.allow_udp_relay {
                                continue;
                            }

                            let flow_control_res = group_handle.flow_control.push(dst_virt_addr, data.len() as u64);

                            if flow_control_res == PushResult::Reject {
                                debug!("group {} udp handler: UDP packet from {} to {} rejected by flow control.", group.name, peer_addr, dst_virt_addr);
                                continue;
                            }

                            let mut fut = None;

                            {
                                let guard = group_handle.mapping.read();

                                if let Some(handle) = guard.get(&dst_virt_addr) {
                                    let relay = handle.node.load().mode.relay.clone();

                                    for np in relay {
                                        match np {
                                            NetProtocol::TCP => {
                                                let mut buff = allocator::alloc(TCP_MSG_HEADER_LEN + size_of::<VirtualAddr>() + data.len());
                                                buff[TCP_MSG_HEADER_LEN + size_of::<VirtualAddr>()..].copy_from_slice(data);
                                                TcpMsg::relay_encode(key, rng.random(), dst_virt_addr, data.len(), &mut buff);

                                                match handle.tx.try_send(buff) {
                                                    Ok(_) => {
                                                        if log::max_level() >= log::Level::Debug {
                                                            let f = || {
                                                                let src = get_ip_src_addr(data)?;
                                                                let dst = get_ip_dst_addr(data)?;
                                                                Result::<_, anyhow::Error>::Ok((src, dst))
                                                            };

                                                            if let Ok((src, dst)) = f() {
                                                                debug!("group {} udp handler: tcp message relay to {}; packet {}->{}", group.name, dst_virt_addr, src, dst);
                                                            }
                                                        }
                                                        break;
                                                    }
                                                    Err(e) => warn!("Failed to send packet to TCP channel for group {}: {}", group.name, e)
                                                }
                                            }
                                            NetProtocol::UDP => {
                                                let status = handle.udp_status.load();

                                                let dst_addr = match status {
                                                    UdpStatus::Available { dst_addr } => dst_addr,
                                                    UdpStatus::Unavailable => continue
                                                };

                                                drop(guard);

                                                if log::max_level() >= log::Level::Debug {
                                                    let f = || {
                                                        let src = get_ip_src_addr(data)?;
                                                        let dst = get_ip_dst_addr(data)?;
                                                        Result::<_, anyhow::Error>::Ok((src, dst))
                                                    };

                                                    if let Ok((src, dst)) = f() {
                                                        debug!("group {} udp handler: udp message relay to {}; packet {}->{}", group.name, dst_virt_addr, src, dst);
                                                    }
                                                }

                                                UdpMsg::relay_encode(key, rng.random(), dst_virt_addr, data.len(), packet);
                                                fut = Some(UdpMsg::send_msg(&socket, packet, dst_addr));
                                                break;
                                            }
                                        }
                                    }
                                }
                            };

                            if let Some(fut) = fut {
                                match fut.await {
                                    Ok(_) => (),
                                    Err(UdpSocketErr::FatalError(e)) => return Result::<(), _>::Err(anyhow!("UDP relay for group '{}' encountered a fatal socket error while forwarding packet: {}", group.name, e)),
                                    Err(UdpSocketErr::SuppressError(e)) => {
                                        warn!("Failed to send UDP packet for group {}: {}", group.name, e);
                                    }
                                }
                            }
                        }
                        UdpMsg::KcpData(data) => {
                            let mut send_fut = None;
                            let conv = kcp::get_conv(data);

                            {
                                let kcp_sessions_guard = kcp_sessions.read();
                                let mut kcp_sessions_write_guard;
                                let sessions = &*kcp_sessions_guard;

                                let tx = match sessions.binary_search_by_key(&conv, |(k, _)| *k) {
                                    Ok(i) => {
                                        &sessions[i].1
                                    }
                                    Err(_) => {
                                        drop(kcp_sessions_guard);

                                        {
                                            if kcp_sessions_expired_list.read().contains(&conv) {
                                                continue;
                                            }
                                        }

                                        kcp_sessions_write_guard = kcp_sessions.write();
                                        let sessions = &mut *kcp_sessions_write_guard;

                                        match sessions.binary_search_by_key(&conv, |(k, _)| *k) {
                                            Ok(i) => {
                                                &sessions[i].1
                                            }
                                            Err(i) => {
                                                let kcp_sessions = kcp_sessions.clone();
                                                let (stack_tx, mut stack_rx) = tokio::sync::mpsc::channel(1024);
                                                let socket = socket.clone();
                                                let (handler_kcp_channel, handler_tcp_channel) = tokio::io::duplex(8192);
                                                let kcp_sessions_expired_list = kcp_sessions_expired_list.clone();

                                                tokio::spawn(async move {
                                                    info!("group {} udp handler: KCP session (conv: {}) initiated with peer {}.", group.name, conv, peer_addr);
                                                    // destruction immediately after the connection is terminated, rather than the entire life cycle
                                                    let block_on = async move {
                                                        let (mut rx, mut tx) = tokio::io::split(handler_tcp_channel);

                                                        let mut stack = KcpStack::new(
                                                            &socket,
                                                            peer_addr,
                                                            conv,
                                                            &mut tx,
                                                            &mut rx,
                                                            &mut stack_rx,
                                                            key,
                                                        );

                                                        stack.block_on().await
                                                    };

                                                    let res = block_on.await;
                                                    kcp_sessions_expired_list.write().insert(conv);

                                                    {
                                                        let mut kcp_sessions_guard = kcp_sessions.write();
                                                        let sessions = &mut *kcp_sessions_guard;
                                                        let remove_index = sessions.binary_search_by_key(&conv, |(k, _)| *k).unwrap();
                                                        sessions.remove(remove_index);
                                                    }

                                                    if let Err(e) = res {
                                                        warn!("KCP transport session failed: {:?}", e);
                                                    }

                                                    tokio::time::sleep(Duration::from_secs(5 * 60)).await;
                                                    kcp_sessions_expired_list.write().remove(&conv);
                                                });
        
                                                send_fut = Some(kcp_acceptor_channel.send((handler_kcp_channel, peer_addr)));
        
                                                sessions.insert(i, (conv, stack_tx));
                                                &sessions[i].1
                                            }
                                        }
                                    }
                                };

                                let mut packet = allocator::alloc(data.len());
                                packet.copy_from_slice(data);
                                let _ = tx.try_send(packet);
                            }

                            if let Some(fut) = send_fut {
                                fut.await?;
                            }
                        }
                        _ => error!("Received invalid UDP message for group {}", group.name),
                    };
                };
            };

            tokio::select! {
                res = fut => res,
                _ = notified.changed() => Err(anyhow!("UDP receiver for group '{}' aborted due to notification.", group.name))
            }
        }).await?
    };

    tokio::try_join!(heartbeat_schedule, recv_handler)?;
    Ok(())
}
