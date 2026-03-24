mod types;
mod pool;
mod tunnel;
mod udp;
mod tcp;

mod api;
mod info_tui;

pub(crate) use types::{GroupHandle, GroupInfo};

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{watch, Notify};

use crate::common::cipher::Cipher;
use crate::server::api::api_start;
use crate::server::info_tui::App;
use crate::ServerConfigFinalize;

pub async fn start<K>(config: ServerConfigFinalize<K>) -> Result<()>
where
    K: Cipher + Clone + Send + Sync + 'static,
{
    let config = &*Box::leak(Box::new(config));
    let mut futures = Vec::with_capacity(config.groups.len());
    let mut group_handles = Vec::with_capacity(config.groups.len());

    for group in &config.groups {
        let gh = Arc::new(GroupHandle::new(config.channel_limit, group));
        group_handles.push(gh.clone());

        let fut = async {
            let listen_addr = group.listen_addr;

            let udp_socket = UdpSocket::bind(listen_addr)
                .await
                .with_context(|| format!("Failed to bind UDP socket for group '{}' to address '{}'. Ensure the address is available and permissions are correct.", group.name, listen_addr))?;

            let udp_socket = Arc::new(udp_socket);

            info!("UDP socket for group {} is listening on {}", group.name, listen_addr);

            let tcp_listener = TcpListener::bind(listen_addr)
                .await
                .with_context(|| format!("Failed to bind TCP listener for group '{}' to address '{}'. Ensure the address is available and permissions are correct.", group.name, listen_addr))?;

            info!("TCP listener for group {} is listening on {}", group.name, listen_addr);

            let (_notify, notified) = watch::channel(());
            let gh1 = gh.clone();

            let (kcp_acceptor_channel_tx, kcp_acceptor_channel_rx) =
                tokio::sync::mpsc::channel(1024);

            let udp_handle = async {
                let fut = udp::udp_handler(
                    group,
                    udp_socket.clone(),
                    gh1,
                    config.udp_heartbeat_interval,
                    config.udp_heartbeat_continuous_loss,
                    config.udp_heartbeat_continuous_recv,
                    notified.clone(),
                    kcp_acceptor_channel_tx,
                );

                fut.await
                    .context(format!("UDP handler for group '{}' encountered an error.", group.name))
            };

            let tcp_handle = async {
                let mut notified = notified.clone();

                let fut = tcp::tcp_handler(
                    tcp_listener,
                    udp_socket.clone(),
                    config,
                    group,
                    gh,
                    notified.clone(),
                    kcp_acceptor_channel_rx,
                );

                tokio::spawn(async move {
                    tokio::select! {
                        res = fut => res,
                        _ = notified.changed() => Err(anyhow::anyhow!("abort task"))
                    }
                })
                .await?
                .context(format!(
                    "TCP handler for group '{}' encountered an error.",
                    group.name
                ))
            };

            tokio::try_join!(udp_handle, tcp_handle).map(|_| ())
        };

        futures.push(async {
            info!("Starting server for group {}...", group.name);

            if let Err(e) = fut.await {
                error!("Server for group {} failed: {:?}", group.name, e)
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
