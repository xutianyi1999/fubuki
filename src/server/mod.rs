mod types;
mod pool;
mod tunnel;
mod udp;
mod tcp;

mod api;
mod info_tui;

pub(crate) use types::{GroupHandle, GroupInfo};

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, watch, Notify};

use crate::common::cipher::Cipher;
use crate::server::api::api_start;
use crate::server::info_tui::App;
use crate::server::pool::{AddressPool, NoncePool};
use crate::ServerConfigFinalize;

pub(crate) struct AddrGroupEntry<K: Cipher + 'static> {
    pub(crate) group: &'static crate::GroupFinalize<K>,
    pub(crate) handle: Arc<GroupHandle>,
    pub(crate) nonce_pool: Arc<NoncePool>,
    pub(crate) address_pool: Arc<AddressPool>,
}

pub(crate) type KcpChannel = mpsc::Sender<(tokio::io::DuplexStream, std::net::SocketAddr, usize)>;

pub async fn start<K>(config: ServerConfigFinalize<K>) -> Result<()>
where
    K: Cipher + Clone + Send + Sync + 'static,
{
    let config = &*Box::leak(Box::new(config));
    let mut group_handles = Vec::with_capacity(config.groups.len());
    let mut addr_group_entries: HashMap<std::net::SocketAddr, Vec<AddrGroupEntry<K>>> = HashMap::new();

    for group in &config.groups {
        let gh = Arc::new(GroupHandle::new(config.channel_limit, group));
        group_handles.push(gh.clone());
        addr_group_entries
            .entry(group.listen_addr)
            .or_default()
            .push(AddrGroupEntry {
                group,
                handle: gh,
                nonce_pool: Arc::new(NoncePool::new()),
                address_pool: Arc::new(AddressPool::new(group.address_range).unwrap()),
            });
        info!("AddressPool for group '{}' initialized with range {}.", group.name, group.address_range);
    }

    let mut futures = Vec::with_capacity(addr_group_entries.len());

    for (listen_addr, entries) in addr_group_entries {
        let entries: &'static [AddrGroupEntry<K>] = Box::leak(entries.into_boxed_slice());
        let group_names: Vec<String> = entries.iter().map(|e| e.group.name.clone()).collect();

        let fut = async move {
            let udp_socket = UdpSocket::bind(listen_addr)
                .await
                .with_context(|| format!("Failed to bind UDP socket for address '{}'. Ensure the address is available and permissions are correct.", listen_addr))?;
            let udp_socket = Arc::new(udp_socket);
            info!("UDP socket is listening on {}", listen_addr);

            let tcp_listener = TcpListener::bind(listen_addr)
                .await
                .with_context(|| format!("Failed to bind TCP listener for address '{}'. Ensure the address is available and permissions are correct.", listen_addr))?;
            info!("TCP listener is listening on {}", listen_addr);

            let (_notify, notified) = watch::channel(());
            let (kcp_tx, kcp_rx) = mpsc::channel(1024);

            let udp_sock = udp_socket.clone();
            let notif_udp = notified.clone();
            let udp_handle = async move {
                let fut = udp::udp_handler(
                    entries,
                    udp_sock,
                    config.udp_heartbeat_interval,
                    config.udp_heartbeat_continuous_loss,
                    config.udp_heartbeat_continuous_recv,
                    notif_udp,
                    kcp_tx,
                );
                fut.await
                    .context(format!("UDP handler for address '{}' encountered an error.", listen_addr))
            };

            let mut notif_tcp = notified;
            let tcp_handle = async move {
                let handler_notified = notif_tcp.clone();

                let fut = tcp::tcp_handler(
                    tcp_listener,
                    udp_socket,
                    config,
                    entries,
                    handler_notified,
                    kcp_rx,
                );

                tokio::spawn(async move {
                    tokio::select! {
                        res = fut => res,
                        _ = notif_tcp.changed() => Err(anyhow::anyhow!("abort task"))
                    }
                })
                .await?
                .context(format!("TCP handler for address '{}' encountered an error.", listen_addr))
            };

            tokio::try_join!(udp_handle, tcp_handle).map(|_| ())
        };

        futures.push(async move {
            info!("Starting server for address {} (groups: {})...", listen_addr, group_names.join(", "));
            if let Err(e) = fut.await {
                error!("Server for address {} failed: {:?}", listen_addr, e)
            }
        });
    }

    let handle = async {
        futures_util::future::join_all(futures).await;
        Ok(())
    };

    let restart_notify = Arc::new(Notify::new());
    let api_handle = api_start(config.api_addr, group_handles, restart_notify.clone());

    tokio::select! {
        res = async { tokio::try_join!(handle, api_handle) } => { res?; }
        _ = restart_notify.notified() => {
            info!("Restart signal received, initiating restart");
            crate::SHOULD_RESTART.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
    Ok(())
}

pub async fn info(api_addr: &str) -> Result<()> {
    let mut info_app = App::new(api_addr.to_string());
    let mut terminal = ratatui::init();
    let res = info_app.run(&mut terminal).await;
    ratatui::restore();
    res
}
