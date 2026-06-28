use std::mem::size_of;
use std::ops::Deref;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ahash::{HashMap, HashMapExt};
use anyhow::{anyhow, Result};
use chrono::Utc;
use rand::{Rng, SeedableRng};
use tokio::io::{AsyncRead, AsyncWrite, BufReader};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::{sync, time};

use crate::common::allocator;
use crate::common::cipher::Cipher;
use crate::common::net::protocol::{
    GroupContent, HeartbeatType, NetProtocol, Node, Register, RegisterError, Seq, TcpMsg, UdpMsg,
    UdpSocketErr, VirtualAddr, TCP_BUFF_SIZE, TCP_MSG_HEADER_LEN, UDP_MSG_HEADER_LEN,
};
use crate::common::net::{PushResult, UdpStatus};
use crate::GroupFinalize;
use crate::ServerConfigFinalize;

use super::pool::{AddressPool, NoncePool};
use super::types::{Bridge, GroupHandle, NodeHandle, NodeMap};

pub(crate) struct Tunnel<K: 'static, R, W> {
    pub(crate) config: &'static ServerConfigFinalize<K>,
    pub(crate) group: &'static GroupFinalize<K>,
    stream: Option<(R, W)>,
    udp_socket: Arc<UdpSocket>,
    group_handle: Arc<GroupHandle>,
    nonce_pool: Arc<NoncePool>,
    address_pool: Arc<AddressPool>,
    pub(crate) register: Option<Register>,
    bridge: Option<Bridge>,
    node_handle: Option<Arc<NodeHandle>>,
}

impl<K, R, W> Tunnel<K, R, W> 
    where 
        K: Cipher + Clone + Send + Sync,
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
{
    pub(crate) fn new(
        stream: (R, W),
        udp_socket: Arc<UdpSocket>,
        config: &'static ServerConfigFinalize<K>,
        group: &'static GroupFinalize<K>,
        group_handle: Arc<GroupHandle>,
        nonce_pool: Arc<NoncePool>,
        address_pool: Arc<AddressPool>,
    ) -> Self {
        Self {
            stream: Some(stream),
            udp_socket,
            config,
            group,
            group_handle,
            nonce_pool,
            address_pool,
            register: None,
            bridge: None,
            node_handle: None
        }
    }

    async fn init(&mut self) -> Result<()> {
        let buff = &mut allocator::alloc(1024);
        let (reader, writer) = self.stream.as_mut().unwrap();
        let key = &self.group.key;
        let mut rng = rand::rngs::SmallRng::from_os_rng();
        let group = self.group;

        loop {
            let nonce_pool = &self.nonce_pool;
            let msg = TcpMsg::read_msg(reader, key, buff).await?
                .ok_or_else(|| anyhow!("Node connection closed unexpectedly during initialization for group '{}'.", group.name))?;

            match msg {
                TcpMsg::GetIdleVirtualAddr => {
                    debug!("group {} tunnel init: received GetIdleVirtualAddr request.", group.name);
                    let addr = self.address_pool.get_idle_addr()
                        .map(|v| (v, self.group.address_range));
                    let len = TcpMsg::get_idle_virtual_addr_res_encode(key, rng.random(), addr, buff)?;
                    TcpMsg::write_msg(writer, &buff[..len]).await?;
                    if let Some((v_addr, _)) = addr {
                        debug!("group {} tunnel init: sent GetIdleVirtualAddr response with allocated address {}.", group.name, v_addr);
                    } else {
                        debug!("group {} tunnel init: sent GetIdleVirtualAddr response, but no idle address found.", group.name);
                    }
                }
                TcpMsg::Register(msg) => {
                    let now = Utc::now().timestamp();
                    let remain = now - msg.register_time;

                    if !(-300..=300).contains(&remain) {
                        let len = TcpMsg::register_res_encode(key, rng.random(), &Err(RegisterError::Timeout), buff)?;
                        TcpMsg::write_msg(writer, &buff[..len]).await?;
                        return Err(anyhow!("Node registration for group '{}' failed: registration message timed out ({}s elapsed, max 300s).", group.name, remain));
                    }

                    let not_contained = nonce_pool.set.lock().insert(msg.nonce);
                    debug!("group {} tunnel init: nonce {} added to pool (new: {}).", group.name, msg.nonce, not_contained);

                    if !not_contained {
                        let len = TcpMsg::register_res_encode(key, rng.random(), &Err(RegisterError::NonceRepeat), buff)?;
                        TcpMsg::write_msg(writer, &buff[..len]).await?;
                        return Err(anyhow!("Node registration for group '{}' failed: nonce ({}) has already been used.", group.name, msg.nonce));
                    }

                    let nonce_pool = nonce_pool.clone();
                    let nonce = msg.nonce;

                    tokio::spawn(async move {
                        time::sleep(Duration::from_secs(300 * 2)).await;
                        nonce_pool.set.lock().remove(&nonce);
                        debug!("group {} tunnel init: nonce {} removed from pool after timeout.", group.name, nonce);
                    });

                    if let Err(e) = self.address_pool.allocate(msg.virtual_addr) {
                        let len = TcpMsg::register_res_encode(key, rng.random(), &Err(RegisterError::InvalidVirtualAddress(e)), buff)?;
                        TcpMsg::write_msg(writer, &buff[..len]).await?;
                        return Err(anyhow!("Node registration for group '{}' failed: IP address allocation error: {}", group.name, e));
                    };

                    self.register = Some(msg.clone());

                    let node = Node {
                        name: msg.node_name,
                        virtual_addr: msg.virtual_addr,
                        lan_udp_addr: msg.lan_udp_socket_addr,
                        wan_udp_addr: None,
                        mode: msg.proto_mod,
                        allowed_ips: msg.allowed_ips,
                        register_time: msg.register_time,
                        register_nonce: msg.nonce
                    };
                    let (bridge, node_handle) = self.group_handle.join(node)?;
                    self.bridge = Some(bridge);
                    self.node_handle = Some(node_handle);

                    let gc = GroupContent {
                        name: group.name.clone(),
                        cidr: self.group.address_range,
                        allow_udp_relay: self.group.allow_udp_relay,
                        allow_tcp_relay: self.group.allow_tcp_relay
                    };

                    let len = TcpMsg::register_res_encode(key, rng.random(), &Ok(gc), buff)?;
                    return TcpMsg::write_msg(writer,  &buff[..len]).await;
                }
                _ => return Err(anyhow!("Received an invalid or unexpected message during tunnel initialization for group '{}'.", group.name)),
            }
        }
    }

    pub(crate) async fn exec(&mut self) -> Result<()> {
        self.init().await?;

        info!("Node {} successfully registered via TCP.", self.register.as_ref().unwrap().node_name);

        let (mut bridge, node_handle) = match (self.bridge.take(), &self.node_handle) {
            (Some(bridge), Some(node_handle)) => (bridge, &*node_handle),
            _ => unreachable!(),
        };

        let (rx, mut tx) = self.stream
            .take()
            .unwrap();

        let mut rx = BufReader::with_capacity(TCP_BUFF_SIZE, rx);
        let (local_channel_tx, mut local_channel_rx) = mpsc::unbounded_channel();
        let (_notify, notified) = sync::watch::channel(());
        let key = &self.group.key;

        let heartbeat_schedule = async {
            let mut notified = notified.clone();
            let node_handle = node_handle.clone();
            let config = self.config;
            let local_channel_tx = local_channel_tx.clone();
            let register = self.register.clone().unwrap();
            let group = self.group;

            tokio::spawn(async move {
                let fut = async {
                    let mut rng = rand::rngs::SmallRng::from_os_rng();

                    loop {
                        let seq = {
                            let hc = &node_handle.tcp_heartbeat_cache;

                            let mut hc = hc.write();
                            hc.check();

                            if hc.packet_continuous_loss_count >= config.tcp_heartbeat_continuous_loss {
                                return Err(anyhow!("TCP heartbeat for node {}({}) in group '{}' timed out. No response received.", register.node_name, register.virtual_addr, group.name))
                            }

                            hc.ping();
                            hc.seq
                        };

                        let mut buff = allocator::alloc(TCP_MSG_HEADER_LEN + size_of::<Seq>() + size_of::<HeartbeatType>());
                        TcpMsg::heartbeat_encode(key, rng.random(), seq, HeartbeatType::Req, &mut buff);

                        local_channel_tx.send(buff).map_err(|e| anyhow!("Failed to send heartbeat packet to local channel for node {}({}) in group '{}': {}", register.node_name, register.virtual_addr, group.name, e))?;
                        tokio::time::sleep(config.tcp_heartbeat_interval).await;
                    }
                };

                tokio::select! {
                    res = fut => res,
                    _ = notified.changed() => Err(anyhow!("TCP heartbeat schedule for node {}({}) in group '{}' aborted due to notification.", register.node_name, register.virtual_addr, group.name))
                }
            }).await?
        };

        let recv_handler = async {
            let mut notified = notified.clone();
            let group_handle = self.group_handle.clone();
            let node_handle = node_handle.clone();
            let udp_socket = self.udp_socket.clone();
            let group = self.group;
            let local_channel_tx = local_channel_tx.clone();
            let register = self.register.clone().unwrap();

            tokio::spawn(async move {
                let fut = async {
                    let mut buff = vec![0u8; TCP_BUFF_SIZE];
                    let mut rng = rand::rngs::SmallRng::from_os_rng();

                    loop {
                        let sub_buff = &mut buff[UDP_MSG_HEADER_LEN..];
                        let msg = TcpMsg::read_msg(&mut rx, key, sub_buff).await?;

                        let msg = match msg {
                            None => return Ok(()),
                            Some(msg) => msg
                        };

                        match msg {
                            TcpMsg::Relay(dst_virt_addr, packet) => {
                                if !group.allow_tcp_relay {
                                    continue;
                                }

                                let flow_control_res = group_handle.flow_control.push(dst_virt_addr, packet.len() as u64);

                                if flow_control_res == PushResult::Reject {
                                    debug!("group {} tcp handler: TCP packet to {} rejected by flow control.", group.name, dst_virt_addr);
                                    continue;
                                }

                                let mut fut = None;
                                {
                                    let guard = group_handle.mapping.read();

                                    if let Some(handle) = guard.get(&dst_virt_addr) {
                                        let node = handle.node.load();

                                        for np in &node.mode.relay {
                                            match np {
                                                NetProtocol::TCP => {
                                                    let mut buff = allocator::alloc(TCP_MSG_HEADER_LEN + size_of::<VirtualAddr>() + packet.len());
                                                    buff[TCP_MSG_HEADER_LEN + size_of::<VirtualAddr>()..].copy_from_slice(packet);
                                                    TcpMsg::relay_encode(key, rng.random(), dst_virt_addr, packet.len(), &mut buff);

                                                    match handle.tx.try_send(buff) {
                                                        Ok(_) => {
                                                            debug!("tcp handler: tcp message relay to node {}", node.name);
                                                            break;
                                                        },
                                                        Err(e) => warn!("Failed to send packet to TCP channel for group {}: {}", group.name, e)
                                                    }
                                                }
                                                NetProtocol::UDP =>  {
                                                    let udp_status = handle.udp_status.load();

                                                    let addr = match udp_status {
                                                        UdpStatus::Available { dst_addr } => dst_addr,
                                                        UdpStatus::Unavailable => continue
                                                    };

                                                    debug!("tcp handler: udp message relay to node {}", node.name);

                                                    drop(node);
                                                    drop(guard);

                                                    let packet_len = packet.len();
                                                    let len = UdpMsg::relay_encode(key, rng.random(), dst_virt_addr, packet_len, &mut buff);

                                                    fut = Some(UdpMsg::send_msg(&udp_socket, &buff[..len], addr));
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }

                                if let Some(fut) = fut {
                                                                    match fut.await {
                                                                        Ok(_) => (),
                                                                        Err(UdpSocketErr::FatalError(e)) => return Err(anyhow!("TCP receiver for node {}({}) in group '{}' encountered a fatal UDP socket error during relay: {}", register.node_name, register.virtual_addr, group.name, e)),                                        Err(UdpSocketErr::SuppressError(e)) => {
                                            warn!("Failed to send UDP packet for group {}: {}", group.name, e);
                                        }
                                    }
                                }
                            }
                            TcpMsg::Heartbeat(seq, HeartbeatType::Req) => {
                                let mut buff = allocator::alloc(TCP_MSG_HEADER_LEN + size_of::<Seq>() + size_of::<HeartbeatType>());
                                TcpMsg::heartbeat_encode(key, rng.random(), seq, HeartbeatType::Resp, &mut buff);

                                local_channel_tx.send(buff).map_err(|e| anyhow!("Failed to send heartbeat response to local channel for node {}({}) in group '{}': {}", register.node_name, register.virtual_addr, group.name, e))?;
                            }
                            TcpMsg::Heartbeat(recv_seq, HeartbeatType::Resp) => {
                                node_handle.tcp_heartbeat_cache.write().reply(recv_seq);
                            }
                            TcpMsg::UploadPeers(peers) => {
                                *node_handle.peers_status.write() = Some((peers, Instant::now()));
                            }
                            TcpMsg::FetchPeers => {
                                let mut peers = HashMap::new();
                                let mapping_guard = group_handle.mapping.read();

                                for (&addr, node_handle) in mapping_guard.deref() {
                                    let peers_status = node_handle.peers_status.read();

                                    if let Some((peers_status, update_time)) = peers_status.deref() {
                                        if update_time.elapsed() < Duration::from_secs(10) &&
                                            !peers_status.is_empty()
                                        {
                                            peers.insert(addr, peers_status.clone());
                                        }
                                    }
                                }

                                drop(mapping_guard);

                                let len = TcpMsg::fetch_peers_res_encode(key, rng.random(), &peers, &mut buff)?;
                                let mut data = allocator::alloc(len);
                                data.copy_from_slice(&buff[..len]);
                                local_channel_tx.send(data).map_err(|e| anyhow!("Failed to send fetched peers to local channel for node {}({}) in group '{}': {}", register.node_name, register.virtual_addr, group.name, e))?;
                            }
                            _ => return Result::<()>::Err(anyhow!("Received an invalid or unexpected TCP message from node {}({}) in group '{}'.", register.node_name, register.virtual_addr, group.name)),
                        }
                    }
                };

                tokio::select! {
                    res = fut => res,
                    _ = notified.changed() => Err(anyhow!("TCP receiver for node {}({}) in group '{}' aborted due to notification.", register.node_name, register.virtual_addr, group.name))
                }
            }).await?
        };

        let send_handler = async {
            let mut notified = notified.clone();
            let register = self.register.clone().unwrap();
            let group = self.group;

            tokio::spawn(async move {
                let mut buff = vec![0u8; TCP_BUFF_SIZE];
                let mut rng = rand::rngs::SmallRng::from_os_rng();

                loop {
                    tokio::select! {
                        res = bridge.watch_rx.changed() => {
                            if let Err(e) = res {
                                return Result::<(), _>::Err(anyhow!("Watch channel for node {}({}) in group '{}' failed: {}", register.node_name, register.virtual_addr, group.name, e));
                            }

                            let node_list: Arc<NodeMap> = bridge.watch_rx.borrow().clone();
                            let len = TcpMsg::node_map_encode(key, rng.random(), &node_list, &mut buff)?;
                            TcpMsg::write_msg(&mut tx, &buff[..len]).await?;
                        }
                        res = bridge.channel_rx.recv() => {
                            let buff = res.ok_or_else(|| anyhow!("Bridge channel for node {}({}) in group '{}' closed unexpectedly.", register.node_name, register.virtual_addr, group.name))?;
                            TcpMsg::write_msg(&mut tx, &buff).await?;
                        }
                        res = local_channel_rx.recv() => {
                            let buff = res.ok_or_else(|| anyhow!("Local channel for node {}({}) in group '{}' closed unexpectedly.", register.node_name, register.virtual_addr, group.name))?;
                            TcpMsg::write_msg(&mut tx, &buff).await?;
                        }
                        _ = notified.changed() => return Err(anyhow!("TCP sender for node {}({}) in group '{}' aborted due to notification.", register.node_name, register.virtual_addr, group.name))
                    }
                }
            }).await?
        };

        // A single task ends normally
        tokio::select! {
            res = heartbeat_schedule => res,
            res = recv_handler => res,
            res = send_handler => res,
        }
    }
}

impl<T, R, W> Drop for Tunnel<T, R, W> {
    fn drop(&mut self) {
        if let Some(reg) = &self.register {
            {
                let mut guard = self.group_handle.mapping.write();

                if guard.remove(&reg.virtual_addr).is_some() {
                    self.group_handle.sync(&guard).expect("FATAL: Failed to synchronize node map during tunnel drop. This indicates a serious internal consistency issue.");
                }
            }

            self.group_handle.flow_control.remove_address(&reg.virtual_addr);
            self.address_pool.inner.lock().release(&reg.virtual_addr)
        }
    }
}
