use std::{
    mem::size_of,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    ops::Deref,
    sync::{
        atomic::{AtomicI64, Ordering},
        Arc, OnceLock,
    },
    time::Duration,
};
use std::pin::Pin;

use anyhow::{Context, Result};
use arc_swap::{ArcSwap, Cache};
use chrono::Utc;
use futures_util::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use netstack_lwip::NetStack;
use tokio::net::{TcpSocket, UdpSocket};

use crate::{
    common::{
        cipher::Cipher,
        hook::Hooks,
        net::protocol::{VirtualAddr, UDP_BUFF_SIZE, UDP_MSG_HEADER_LEN},
    },
    routing_table::RoutingTable,
    tun::TunDevice,
};

use super::{Direction, Interface, PacketSender, RoutingTableEnum};

pub struct SNat {
    netstack_sink: tokio::sync::Mutex<SplitSink<Pin<Box<NetStack>>, Vec<u8>>>,
}

async fn udp_inbound_handler(
    udp_inbound: Pin<Box<netstack_lwip::UdpSocket>>,
) -> Result<()> {
    let mapping: Arc<ArcSwap<Vec<Arc<(SocketAddr, UdpSocket, AtomicI64)>>>> =
        Arc::new(ArcSwap::from_pointee(Vec::new()));
    let (tx, mut rx) = netstack_lwip::UdpSocket::split(udp_inbound);
    let tx = Arc::new(tx);

    let mut mapping_cache = Cache::new(&*mapping);

    while let Some((pkt, from, to)) = rx.next().await {
        let snap = mapping_cache.load();

        let item = snap
            .binary_search_by_key(&from, |v| (**v).0)
            .ok()
            .map(|i| &*snap.deref()[i]);

        let insert_item;

        let (_, to_socket, update_time) = match item {
            None => {
                let bind_addr = match to {
                    SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
                };

                let to_socket = UdpSocket::bind(bind_addr).await?;

                insert_item = Arc::new((from, to_socket, AtomicI64::new(Utc::now().timestamp())));

                mapping.rcu(|v| {
                    let mut tmp = (**v).clone();

                    match tmp.binary_search_by_key(&from, |v| (**v).0) {
                        Ok(_) => unreachable!(),
                        Err(i) => tmp.insert(i, insert_item.clone()),
                    }
                    tmp
                });

                tokio::spawn({
                    let tx = tx.clone();
                    let mapping = mapping.clone();
                    let insert_item = insert_item.clone();

                    async move {
                        let (_, to_socket, update_time) = &*insert_item;
                        let mut buff = vec![0u8; 65536];

                        let fut1 = async {
                            loop {
                                let (len, peer) = to_socket.recv_from(&mut buff).await?;
                                debug!("recv from {} to {}", peer, from);
                                tx.send_to(&buff[..len], &peer, &from)?;
                                update_time.store(Utc::now().timestamp(), Ordering::Relaxed);
                            }
                        };

                        let fut2 = async {
                            loop {
                                tokio::time::sleep(Duration::from_secs(5)).await;

                                if Utc::now().timestamp() - update_time.load(Ordering::Relaxed)
                                    > 300
                                {
                                    return;
                                }
                            }
                        };

                        let res: Result<()> = tokio::select! {
                            res = fut1 => res,
                            _ = fut2 => Ok(())
                        };

                        if let Err(e) = res {
                            error!("child udp handler error: {}", e);
                        }

                        mapping.rcu(|v| {
                            let mut tmp = (**v).clone();

                            match tmp.binary_search_by_key(&from, |v| (**v).0) {
                                Ok(i) => tmp.remove(i),
                                Err(_) => unreachable!(),
                            };
                            tmp
                        });
                    }
                });

                &*insert_item
            }
            Some(v) => v,
        };

        debug!("{} send to {}", from, to);
        to_socket.send_to(&pkt, to).await?;
        update_time.store(Utc::now().timestamp(), Ordering::Relaxed);
    }
    Ok(())
}

async fn tcp_inbound_handler(
    mut listener: Pin<Box<netstack_lwip::TcpListener>>,
) -> Result<()> {
    while let Some((mut inbound_stream, _local_addr, remote_addr)) = listener.next().await {
        tokio::spawn(async move {
            let fut = async {
                let socket = if remote_addr.is_ipv4() {
                    TcpSocket::new_v4()?
                } else {
                    TcpSocket::new_v6()?
                };

                crate::common::net::SocketExt::set_keepalive(&socket)?;

                let mut outbound_stream = socket
                    .connect(remote_addr)
                    .await
                    .with_context(|| format!("connect to {} error", &remote_addr))?;

                tokio::io::copy_bidirectional(&mut inbound_stream, &mut outbound_stream).await?;
                Result::<_, anyhow::Error>::Ok(())
            };

            if let Err(e) = fut.await {
                error!("tcp_inbound_handler error: {:?}", e);
            }
        });
    }
    Ok(())
}

async fn netstatck_handler<T, K, InterRT, ExternRT>(
    mut stack_stream: SplitStream<Pin<Box<NetStack>>>,
    routing_table: Arc<RoutingTableEnum<InterRT, ExternRT>>,
    interfaces: Arc<OnceLock<Vec<Arc<Interface<K>>>>>,
    hooks: Option<Arc<Hooks<K>>>,
    tun: T,
) -> Result<()>
where
    T: TunDevice + Clone + Send + Sync + 'static,
    K: Cipher + Clone + Send + Sync + 'static,
    InterRT: RoutingTable + Send + Sync + 'static,
    ExternRT: RoutingTable + Send + Sync + 'static,
{
    let mut sender = None;
    let mut ifs;
    let mut buff = vec![0u8; UDP_BUFF_SIZE];
    const START: usize = UDP_MSG_HEADER_LEN + size_of::<VirtualAddr>();

    while let Some(pkt) = stack_stream.next().await {
        let packet = pkt?;

        let s = match sender.as_mut() {
            Some(sender) => sender,
            None => {
                if let Some(interfaces) = interfaces.get() {
                    ifs = interfaces.iter().map(|v| &**v).collect::<Vec<_>>();
                } else {
                    continue;
                }

                sender = Some(PacketSender::new(
                    &*routing_table,
                    &ifs,
                    &tun,
                    hooks.as_deref(),
                    None,
                ));
                sender.as_mut().unwrap()
            }
        };

        let packet_range = START..START + packet.len();
        buff[packet_range.clone()].copy_from_slice(&packet);

        s.send_packet(
            Direction::Output,
            packet_range,
            &mut buff,
            true,
            false,
            None,
        ).await?;
    }
    Ok(())
}

impl SNat {
    pub fn create<T, K, InterRT, ExternRT>(
        routing_table: Arc<RoutingTableEnum<InterRT, ExternRT>>,
        interfaces: Arc<OnceLock<Vec<Arc<Interface<K>>>>>,
        tun: T,
        hooks: Option<Arc<Hooks<K>>>,
    ) -> Result<Self>
    where
        T: TunDevice + Clone + Send + Sync + 'static,
        K: Cipher + Clone + Send + Sync + 'static,
        InterRT: RoutingTable + Send + Sync + 'static,
        ExternRT: RoutingTable + Send + Sync + 'static,
    {
        let (stack, tcp_listener, udp_socket) = netstack_lwip::NetStack::new()?;
        let (stack_sink, stack_stream) = stack.split();

        tokio::spawn({
            async move {
                if let Err(e) = tcp_inbound_handler(tcp_listener).await {
                    error!("tcp_inbound_handler error: {:?}", e);
                }
                error!("tcp_inbound_handler exited");
            }
        });

        tokio::spawn(async move {
            if let Err(e) = udp_inbound_handler(udp_socket).await {
                error!("udp_inbound_handler error: {:?}", e);
            }
            error!("udp_inbound_handler exited");
        });

        tokio::spawn(async move {
            if let Err(e) =
                netstatck_handler(stack_stream, routing_table, interfaces, hooks, tun).await
            {
                error!("netstack_handler error: {:?}", e);
            }
            error!("netstatck_handler exited");
        });

        let out = SNat {
            netstack_sink: tokio::sync::Mutex::new(stack_sink),
        };
        Ok(out)
    }

    pub async fn input(&self, packet: &[u8]) -> Result<()> {
        let packet = packet.to_owned();
        let mut sink = self.netstack_sink.lock().await;
        sink.send(packet).await?;
        Ok(())
    }
}
