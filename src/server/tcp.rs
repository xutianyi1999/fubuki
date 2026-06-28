use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, watch};

use crate::common::cipher::{Cipher, CipherContext};
use crate::common::net::protocol::MAGIC_NUM;
use crate::common::net::SocketExt;
use crate::ServerConfigFinalize;

use super::tunnel::Tunnel;
use super::AddrGroupEntry;

fn spawn_tunnel<K, R, W>(
    stream: (R, W),
    peer_addr: SocketAddr,
    udp_socket: Arc<UdpSocket>,
    config: &'static ServerConfigFinalize<K>,
    entry: &'static AddrGroupEntry<K>,
    mut notified: watch::Receiver<()>,
)
where
    K: Cipher + Clone + Send + Sync + 'static,
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let mut tunnel = Tunnel::new(
        stream,
        udp_socket,
        config,
        entry.group,
        entry.handle.clone(),
        entry.nonce_pool.clone(),
        entry.address_pool.clone(),
    );

    let group_name = entry.group.name.clone();

    tokio::spawn(async move {
        let res = tokio::select! {
            res = tunnel.exec() => res,
            _ = notified.changed() => Err(anyhow!("Tunnel execution for group '{}' aborted due to notification.", group_name))
        };

        if let Err(e) = res {
            match &tunnel.register {
                None => error!("Tunnel for address {} in group {} failed: {:?}", peer_addr, group_name, e),
                Some(v) => error!("Tunnel for node {}({}) in group {} failed: {:?}", v.node_name, v.virtual_addr, group_name, e)
            }
        }

        if let Some(v) = &tunnel.register {
            info!("group {} node {}-{} disconnected", group_name, v.node_name, v.virtual_addr);
        }
    });
}

pub(crate) async fn tcp_handler<K: Cipher + Clone + Send + Sync>(
    tcp_listener: TcpListener,
    udp_socket: Arc<UdpSocket>,
    config: &'static ServerConfigFinalize<K>,
    entries: &'static [AddrGroupEntry<K>],
    notified: watch::Receiver<()>,
    mut kcp_acceptor_channel: mpsc::Receiver<(DuplexStream, SocketAddr, usize)>,
) -> Result<()> {
    loop {
        tokio::select! {
            res = tcp_listener.accept() => {
                let (stream, peer_addr) = res.context("Failed to accept incoming TCP connection.")?;
                stream.set_keepalive()?;
                stream.set_nodelay(true)?;

                let mut peek_buf = [0u8; 6];
                if let Err(e) = stream.peek(&mut peek_buf).await {
                    error!("Failed to peek TCP connection from {}: {:?}", peer_addr, e);
                    continue;
                }

                let nonce = u16::from_be_bytes([peek_buf[0], peek_buf[1]]);
                let header = [peek_buf[2], peek_buf[3], peek_buf[4], peek_buf[5]];

                let idx = entries.iter().position(|entry| {
                    let mut test = header;
                    let ctx = CipherContext { offset: 0, nonce };
                    entry.group.key.decrypt(&mut test, &ctx);
                    test[0] == MAGIC_NUM
                });

                let idx = match idx {
                    Some(i) => i,
                    None => {
                        warn!("Unable to identify group for connection from {}. No matching key found.", peer_addr);
                        continue;
                    }
                };

                let entry = &entries[idx];
                let stream = tokio::io::split(stream);
                spawn_tunnel(stream, peer_addr, udp_socket.clone(), config, entry, notified.clone());
            }
            res = kcp_acceptor_channel.recv() => {
                let (stream, peer_addr, group_idx) = res.ok_or_else(|| anyhow!("KCP acceptor channel for address has been unexpectedly closed."))?;
                if group_idx >= entries.len() {
                    error!("KCP session from {} has invalid group index {}.", peer_addr, group_idx);
                    continue;
                }
                let entry = &entries[group_idx];
                let stream = tokio::io::split(stream);
                spawn_tunnel(stream, peer_addr, udp_socket.clone(), config, entry, notified.clone());
            }
        }
    }
}
