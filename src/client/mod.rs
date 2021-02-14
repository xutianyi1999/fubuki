use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use crypto::rc4::Rc4;
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use smoltcp::wire::Ipv4Packet;
use tokio::io::{BufReader, Result};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::time::{Duration, sleep};

use crate::common::proto::{Msg, MsgReader, MsgSocket, MsgWriter, Node, NodeId};
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
    info!("Tun ip addr: {}", tun_addr);
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
        let mut buff = vec![0u8; 65536];

        loop {
            let size = tun_rx.recv_packet(&mut buff)?;
            let slice = &buff[..size];
            let ipv4 = Ipv4Packet::new_unchecked(slice);

            let dest_addr = ipv4.dst_addr();
            let dest_addr = IpAddr::from(dest_addr.0);

            let op = MAPPING.get(&dest_addr);

            if let Some(node) = op {
                if let Some(addr) = node.source_udp_addr {
                    to_remote.blocking_send((slice.to_vec(), addr)).res_auto_convert()?;
                }
            }
        }
    });

    let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
    let udp_rx = &udp_socket;
    let udp_tx1 = &udp_socket;
    let udp_tx2 = &udp_socket;

    let u1 = async move {
        let mut udp_rx = MsgSocket::new(udp_rx, rc4);

        loop {
            let res = udp_rx.recv_msg().await;

            match res {
                Ok((msg, _)) => if let Msg::Data(buff) = msg {
                    to_local.send(buff.to_owned()).await.res_auto_convert()?;
                }
                Err(e) => error!("u1: {}", e)
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
            sleep(Duration::from_secs(3)).await;
            udp_tx.send_msg(Msg::Heartbeat(node_id), server_addr).await?;
        }
    };

    let node = Node {
        id: node_id,
        tun_addr,
        source_udp_addr: None,
    };

    let th = tcp_handle(server_addr, rc4, node);
    info!("Client start");
    // tokio::select! {
    //     res = t1 => res?,
    //     res = t2 => res?,
    //     res = u1 => res,
    //     res = u2 => res,
    //     res = h => res,
    //     res = th => res
    // }

    let res = tokio::select! {
        res = t1 => {
        println!("t1");
         res?
        }
        res = t2 => {
        println!("t2");
        res?
        }
        res = u1 => {
        println!("u1");
        res
        }
        res = u2 => {
        println!("u2");
        res
        }

        res = h => {
        println!("h");
        res
        }
        res = th =>{
         println!("th");
         res
        }
    };
    println!("=============");
    res
}

async fn tcp_handle(server_addr: SocketAddr, rc4: Rc4, node: Node) -> Result<()> {
    loop {
        let node = node.clone();

        let f = || async move {
            let mut stream = TcpStream::connect(server_addr).await?;
            let (rx, tx) = stream.split();

            let mut tx = MsgWriter::new(tx, rc4);
            let mut rx = MsgReader::new(BufReader::new(rx), rc4);

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
            error!("th: {}", e)
        }
    }
}