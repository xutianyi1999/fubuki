use std::collections::HashMap;
use std::error::Error;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use chrono::Utc;
use crypto::rc4::Rc4;
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use smoltcp::wire::Ipv4Packet;
use tokio::net::{TcpStream, UdpSocket};
use tokio::signal;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;
use tokio::time::{Duration, sleep};

use crate::common::net::TcpSocketExt;
use crate::common::persistence::ToJson;
use crate::common::proto::{get_interface_addr, Msg, MsgReader, MsgSocket, MsgWriter, MTU, Node, NodeId};
use crate::tun::{create_device, Rx, Tx};

static MAPPING: Lazy<LocalMapping> = Lazy::new(|| LocalMapping::new());

// tun_addr -> node
pub struct LocalMapping {
    map: RwLock<HashMap<Ipv4Addr, Node>>,
}

impl LocalMapping {
    fn new() -> LocalMapping {
        LocalMapping { map: RwLock::new(HashMap::new()) }
    }

    fn get_all(&self) -> HashMap<Ipv4Addr, Node> {
        (*self.map.read()).clone()
    }

    fn update_all(&self, map: HashMap<Ipv4Addr, Node>) -> () {
        let mut m = self.map.write();
        *m = map;
    }
}

pub async fn start(
    server_addr: SocketAddr,
    rc4: Rc4,
    tun_address: (Ipv4Addr, Ipv4Addr),
) -> Result<(), Box<dyn Error>> {
    let shutdown = Arc::new(AtomicBool::new(false));

    let node_id: NodeId = rand::random();

    let tun_addr = tun_address.0;
    let netmask = tun_address.1;

    let device = create_device(tun_addr, netmask)?;
    info!("Tun adapter ip address: {}", tun_addr);
    let (tun_tx, tun_rx) = device.split();

    let (to_tun, from_socket) = mpsc::unbounded_channel::<Box<[u8]>>();
    let (to_socket, from_tun) = mpsc::unbounded_channel::<(Box<[u8]>, SocketAddr)>();

    let listen_ip = get_interface_addr(server_addr).await?;

    let udp_socket = UdpSocket::bind((listen_ip, 0)).await?;
    let udp_socket_addr = udp_socket.local_addr()?;

    let node = Node {
        id: node_id,
        tun_addr,
        lan_udp_addr: udp_socket_addr,
        source_udp_addr: None,
        register_time: 0,
    };

    tokio::task::spawn_blocking(|| if let Err(e) = stdin() { error!("{}", e) });
    info!("Client start");

    tokio::select! {
        res = mpsc_to_tun(from_socket,tun_tx) => res??,
        res = tun_to_mpsc(to_socket, tun_rx, shutdown.clone(), tun_addr) => res??,
        res = socket_to_mpsc(to_tun, MsgSocket::new(&udp_socket, rc4)) => res?,
        res = mpsc_to_socket(from_tun, MsgSocket::new(&udp_socket, rc4)) => res?,
        res = client_heartbeat_schedule(MsgSocket::new(&udp_socket, rc4),node_id,server_addr,tun_addr) => res?,
        res = client_handler(server_addr, rc4, node) => res?,
        res = signal::ctrl_c() => res?
    }

    shutdown.store(true, Ordering::SeqCst);
    Ok(())
}

fn mpsc_to_tun(
    mut mpsc_rx: UnboundedReceiver<Box<[u8]>>,
    mut tun_tx: Box<dyn Tx>,
) -> JoinHandle<io::Result<()>> {
    tokio::task::spawn_blocking(move || {
        while let Some(packet) = mpsc_rx.blocking_recv() {
            tun_tx.send_packet(&packet)?;
        };
        Ok(())
    })
}

fn tun_to_mpsc(
    mpsc_tx: UnboundedSender<(Box<[u8]>, SocketAddr)>,
    mut tun_rx: Box<dyn Rx>,
    shutdown: Arc<AtomicBool>,
    tun_addr: Ipv4Addr,
) -> JoinHandle<io::Result<()>> {
    tokio::task::spawn_blocking(move || {
        let mut buff = [0u8; MTU];

        while let Ok(size) = tun_rx.recv_packet(&mut buff) {
            if shutdown.load(Ordering::SeqCst) {
                break;
            }

            if size == 0 {
                continue;
            }

            let slice = &buff[..size];
            let ipv4 = Ipv4Packet::new_unchecked(slice);

            let dest_addr = ipv4.dst_addr();
            let dest_addr = Ipv4Addr::from(dest_addr.0);

            let guard = MAPPING.map.read();

            if let Some(dest_node) = guard.get(&dest_addr) {
                if let Some(dest_addr) = dest_node.source_udp_addr {
                    let local_node = guard.get(&tun_addr);

                    if let Some(local_node) = local_node {
                        if let Some(local_addr) = local_node.source_udp_addr {
                            let addr = if local_addr.ip() == dest_addr.ip() {
                                dest_node.lan_udp_addr
                            } else {
                                dest_addr
                            };

                            drop(guard);
                            mpsc_tx.send((slice.into(), addr))
                                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                        }
                    }
                }
            }
        }
        Ok(())
    })
}

async fn socket_to_mpsc(
    mpsc_tx: UnboundedSender<Box<[u8]>>,
    mut socket: MsgSocket<'_>,
) -> Result<(), Box<dyn Error>> {
    loop {
        let res = socket.recv_msg().await;

        if let Ok((msg, _)) = res {
            if let Msg::Data(buff) = msg {
                mpsc_tx.send(buff.into())?;
            }
        }
    }
}

async fn mpsc_to_socket(
    mut mpsc_rx: UnboundedReceiver<(Box<[u8]>, SocketAddr)>,
    mut socket: MsgSocket<'_>,
) -> Result<(), Box<dyn Error>> {
    while let Some((data, peer_addr)) = mpsc_rx.recv().await {
        socket.send_msg(Msg::Data(&data), peer_addr).await?;
    }
    Ok(())
}

async fn client_heartbeat_schedule(
    mut socket: MsgSocket<'_>,
    node_id: NodeId,
    server_addr: SocketAddr,
    tun_addr: Ipv4Addr,
) -> Result<(), Box<dyn Error>> {
    loop {
        socket.send_msg(Msg::Heartbeat(node_id), server_addr).await?;
        let map = MAPPING.get_all();
        let local_node = map.get(&tun_addr).cloned();

        let client_addr_list: Vec<Option<SocketAddr>> = map.into_iter()
            .map(|(_, node)| node.source_udp_addr)
            .filter(|op| op.is_some())
            .collect();

        for dest_addr in client_addr_list {
            let dest_addr = dest_addr.unwrap();

            if let Some(local_node) = &local_node {
                if let Some(local_addr) = local_node.source_udp_addr {
                    if local_addr.ip() == dest_addr.ip() {
                        continue;
                    }
                }
            }
            socket.send_msg(Msg::Heartbeat(node_id), dest_addr).await?;
        }

        sleep(Duration::from_secs(5)).await;
    }
}

async fn client_handler(
    server_addr: SocketAddr,
    rc4: Rc4,
    node: Node,
) -> Result<(), Box<dyn Error>> {
    loop {
        let mut node = node.clone();

        let f = || async move {
            let mut stream = TcpStream::connect(server_addr).await?;
            stream.set_keepalive()?;
            info!("Server connected");
            let (rx, tx) = stream.split();

            let mut tx = MsgWriter::new(tx, rc4);
            let mut rx = MsgReader::new(rx, rc4);

            node.register_time = Utc::now().timestamp();
            tx.write_msg(Msg::Register(node)).await?;

            while let Some(msg) = rx.read_msg().await? {
                if let Msg::NodeMap(map) = msg {
                    let m: HashMap<Ipv4Addr, Node> = map.into_iter()
                        .map(|(_, v)| (v.tun_addr, v))
                        .collect();
                    MAPPING.update_all(m)
                }
            }
            Result::<(), Box<dyn Error>>::Ok(())
        };

        if let Err(e) = f().await {
            error!("Tcp handle error -> {}", e)
        }

        sleep(Duration::from_secs(3)).await;
    }
}

fn stdin() -> io::Result<()> {
    let stdin = std::io::stdin();

    loop {
        let mut cmd = String::new();
        let len = stdin.read_line(&mut cmd)?;

        if len == 0 {
            return Ok(());
        }

        match cmd.trim() {
            "show" => {
                let map = MAPPING.get_all();
                let node_list: Vec<Node> = map.into_iter()
                    .map(|(_, v)| v)
                    .collect();

                let json = node_list.to_json_string_pretty()?;
                println!("{}", json)
            }
            _ => ()
        }
    }
}