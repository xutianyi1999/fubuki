use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use tokio::io::DuplexStream;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, watch};

use crate::common::cipher::Cipher;
use crate::common::net::SocketExt;

use crate::GroupFinalize;
use crate::ServerConfigFinalize;

use super::pool::{AddressPool, NoncePool};
use super::tunnel::Tunnel;
use super::types::GroupHandle;
pub(crate) async fn tcp_handler<K: Cipher + Clone + Send + Sync>(
    tcp_listener: TcpListener,
    udp_socket: Arc<UdpSocket>,
    config: &'static ServerConfigFinalize<K>,
    group: &'static GroupFinalize<K>,
    group_handle: Arc<GroupHandle>,
    notified: watch::Receiver<()>,
    mut kcp_acceptor_channel: mpsc::Receiver<(DuplexStream, SocketAddr)>,
) -> Result<()> {
    let nonce_pool = Arc::new(NoncePool::new());
    let address_pool = Arc::new(AddressPool::new(group.address_range)?);
    info!("AddressPool for group '{}' initialized with range {}.", group.name, group.address_range);

    macro_rules! spawn_task {
        ($stream: expr, $peer_addr: expr) => {{
            let mut tunnel = Tunnel::new(
                $stream,
                udp_socket.clone(),
                config,
                group,
                group_handle.clone(),
                nonce_pool.clone(),
                address_pool.clone(),
            );
    
            let mut notified = notified.clone();
    
            tokio::spawn(async move {
                let res = tokio::select! {
                    res = tunnel.exec() => res,
                    _ = notified.changed() => Err(anyhow!("Tunnel execution for group '{}' aborted due to notification.", group.name))
                };
    
                if let Err(e) = res {
                    match &tunnel.register {
                        None => error!("Tunnel for address {} in group {} failed: {:?}", $peer_addr, group.name, e),
                        Some(v) => error!("Tunnel for node {}({}) in group {} failed: {:?}", v.node_name, v.virtual_addr, group.name, e)
                    }
                }
    
                if let Some(v) = &tunnel.register {
                    info!("group {} node {}-{} disconnected", group.name, v.node_name, v.virtual_addr);
                }
            });
        }};
    }

    loop {
        tokio::select! {
            res = tcp_listener.accept() => {
                let (stream, peer_addr) = res.context(format!("Failed to accept incoming TCP connection on {}. Check listening port and firewall rules.", group.listen_addr))?;

                stream.set_keepalive()?;
                stream.set_nodelay(true)?;

                let stream = stream.into_split();
                spawn_task!(stream, peer_addr);
            }
            res = kcp_acceptor_channel.recv() => {
                let (stream, peer_addr) = res.ok_or_else(|| anyhow!("KCP acceptor channel for group '{}' has been unexpectedly closed.", group.name))?;
                let stream = tokio::io::split(stream);
                spawn_task!(stream, peer_addr);
            }
        }
        
    }
}
