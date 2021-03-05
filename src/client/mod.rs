use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use crypto::rc4::Rc4;
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use smoltcp::wire::Ipv4Packet;
use tokio::io::Result;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::time::{Duration, sleep};

use crate::common::net::TcpSocketExt;
use crate::common::persistence::ToJson;
use crate::common::proto::{get_interface_addr, Msg, MsgReader, MsgSocket, MsgWriter, Node, NodeId};
use crate::common::res::StdResAutoConvert;
use crate::tun::{create_device, Rx, Tx};

static MAPPING: Lazy<LocalMapping> = Lazy::new(|| LocalMapping::new());

pub struct LocalMapping {
    map: RwLock<HashMap<IpAddr, Node>>
}

impl LocalMapping {
    fn new() -> LocalMapping {
        LocalMapping { map: RwLock::new(HashMap::new()) }
    }

    fn get(&self, dest_addr: &IpAddr) -> Option<Node> {
        self.map.read().get(dest_addr).cloned()
    }

    fn get_all(&self) -> HashMap<IpAddr, Node> {
        (*self.map.read()).clone()
    }

    fn update_all(&self, map: HashMap<IpAddr, Node>) -> () {
        let mut m = self.map.write();
        *m = map;
    }
}

pub async fn start(server_addr: SocketAddr,
                   rc4: Rc4,
                   tun_address: (IpAddr, IpAddr)) -> Result<()> {
    let node_id: NodeId = rand::random();

    let tun_addr = tun_address.0;
    let netmask = tun_address.1;

    let device = create_device(tun_addr, netmask)?;
    info!("Tun adapter ip address: {}", tun_addr);
    let (mut tun_tx, mut tun_rx) = device.split();

    let (to_local, mut recv_remote) = mpsc::channel::<Vec<u8>>(100);
    let (to_remote, mut recv_local) = mpsc::channel::<(Vec<u8>, SocketAddr)>(100);

    let t1 = tokio::task::spawn_blocking(move || {
        while let Some(packet) = recv_remote.blocking_recv() {
            tun_tx.send_packet(&packet)?;
        }
        Ok(())
    });

    let t2 = tokio::task::spawn_blocking(move || {
        // 65507 - 1(DATA MODE) = 65506
        let mut buff = vec![0u8; 65506];

        loop {
            let size = tun_rx.recv_packet(&mut buff)?;

            if size == 0 {
                continue;
            }

            let slice = &buff[..size];
            let ipv4 = Ipv4Packet::new_unchecked(slice);

            let dest_addr = ipv4.dst_addr();
            let dest_addr = IpAddr::from(dest_addr.0);

            let op = MAPPING.get(&dest_addr);

            if let Some(dest_node) = op {
                if let Some(dest_addr) = dest_node.source_udp_addr {
                    let local_node = MAPPING.get(&tun_addr);

                    if let Some(local_node) = local_node {
                        if let Some(local_addr) = local_node.source_udp_addr {
                            let addr = if local_addr.ip() == dest_addr.ip() {
                                dest_node.lan_udp_addr
                            } else {
                                dest_addr
                            };
                            to_remote.blocking_send((slice.to_vec(), addr)).res_auto_convert()?;
                        }
                    }
                }
            }
        }
    });

    let listen_ip = get_interface_addr(server_addr).await?;

    let udp_socket = UdpSocket::bind((listen_ip, 0)).await?;
    let udp_socket_addr = udp_socket.local_addr()?;

    let udp_rx = &udp_socket;
    let udp_tx1 = &udp_socket;
    let udp_tx2 = &udp_socket;

    let u1 = async move {
        let mut udp_rx = MsgSocket::new(udp_rx, rc4);

        loop {
            let res = udp_rx.recv_msg().await;

            if let Ok((msg, _)) = res {
                if let Msg::Data(buff) = msg {
                    to_local.send(buff.to_owned()).await.res_auto_convert()?;
                }
            }
        }
    };

    let u2 = async move {
        let mut udp_tx = MsgSocket::new(udp_tx1, rc4);

        while let Some((data, peer_addr)) = recv_local.recv().await {
            udp_tx.send_msg(Msg::Data(&data), peer_addr).await?;
        }
        Ok(())
    };

    let h = async move {
        let mut udp_tx = MsgSocket::new(udp_tx2, rc4);

        loop {
            udp_tx.send_msg(Msg::Heartbeat(node_id), server_addr).await?;
            let map = MAPPING.get_all();
            let local_node = map.get(&tun_addr);

            let client_addr_list: Vec<Option<SocketAddr>> = map.iter()
                .map(|(_, node)| node.source_udp_addr)
                .filter(|op| op.is_some())
                .collect();

            for dest_addr in client_addr_list {
                let dest_addr = dest_addr.unwrap();

                if let Some(local_node) = local_node {
                    if let Some(local_addr) = local_node.source_udp_addr {
                        if local_addr.ip() == dest_addr.ip() {
                            continue;
                        }
                    }
                }
                udp_tx.send_msg(Msg::Heartbeat(node_id), dest_addr).await?;
            }

            sleep(Duration::from_secs(5)).await;
        }
    };

    let node = Node {
        id: node_id,
        tun_addr,
        lan_udp_addr: udp_socket_addr,
        source_udp_addr: None,
    };

    let th = tcp_handle(server_addr, rc4, node);
    let s = tokio::task::spawn_blocking(|| stdin());

    info!("Client start");

    let res = tokio::select! {
        res = t1 => res?,
        res = t2 => res?,
        res = u1 => res,
        res = u2 => res,
        res = h => res,
        res = th => res,
        res = s => res?
    };

    error!("Client crashed");
    res
}

async fn tcp_handle(server_addr: SocketAddr, rc4: Rc4, node: Node) -> Result<()> {
    loop {
        let node = node.clone();

        let f = || async move {
            let mut stream = TcpStream::connect(server_addr).await?;
            stream.set_keepalive()?;
            info!("Server connected");
            let (rx, tx) = stream.split();

            let mut tx = MsgWriter::new(tx, rc4);
            let mut rx = MsgReader::new(rx, rc4);

            tx.write_msg(Msg::Register(node)).await?;

            while let Some(msg) = rx.read_msg().await? {
                if let Msg::NodeMap(map) = msg {
                    let m: HashMap<IpAddr, Node> = map.iter()
                        .map(|(_, v)| (v.tun_addr, v.clone()))
                        .collect();
                    MAPPING.update_all(m)
                }
            }
            Result::Ok(())
        };

        if let Err(e) = f().await {
            error!("Tcp handle error -> {}", e)
        }

        // 尝试修复重连后将原映射覆盖
        sleep(Duration::from_secs(3)).await;
    }
}

fn stdin() -> Result<()> {
    let stdin = std::io::stdin();

    loop {
        let mut cmd = String::new();
        stdin.read_line(&mut cmd)?;

        match cmd.trim() {
            "show" => {
                let map = MAPPING.get_all();
                let node_list: Vec<Node> = map.iter()
                    .map(|(_, v)| v.clone())
                    .collect();

                let json = node_list.to_json_string_pretty()?;
                println!("{}", json)
            }
            _ => ()
        }
    }
}