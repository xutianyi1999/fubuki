#[macro_use]
extern crate log;

use std::env;
use std::fmt::{Display, Formatter, write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::sync::atomic::AtomicI64;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use log4rs::append::console::ConsoleAppender;
use log4rs::Config;
use log4rs::config::{Appender, Root};
use log4rs::encode::pattern::PatternEncoder;
use log::LevelFilter;
use mimalloc::MiMalloc;
use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::runtime::Runtime;

use crate::common::Either;
use crate::common::net::get_interface_addr;
use crate::common::net::proto::ProtocolMode;
use crate::common::rc4::Rc4;

mod tun;
mod server;
mod client;
mod common;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[derive(Deserialize, Clone)]
struct ServerConfig {
    listen_addr: SocketAddr,
    key: String,
}

#[derive(Deserialize, Clone)]
struct TunConfig {
    ip: Ipv4Addr,
    netmask: Ipv4Addr,
}

#[derive(Deserialize, Clone)]
struct NetworkRange {
    server_addr: String,
    tun: TunConfig,
    key: String,
    mode: Option<String>,
    lan_ip_addr: Option<IpAddr>,
    try_send_to_lan_addr: Option<bool>,
}

#[derive(Deserialize, Clone)]
struct ClientConfig {
    mtu: Option<usize>,
    channel_limit: Option<usize>,
    api_addr: Option<SocketAddr>,
    tcp_heartbeat_interval_secs: Option<u64>,
    udp_heartbeat_interval_secs: Option<u64>,
    reconnect_interval_secs: Option<u64>,
    udp_socket_recv_buffer_size: Option<usize>,
    udp_socket_send_buffer_size: Option<usize>,
    network_ranges: Vec<NetworkRange>,
}

#[derive(Clone)]
struct NetworkRangeFinalize {
    server_addr: String,
    tun: TunConfig,
    key: Rc4,
    mode: ProtocolMode,
    lan_ip_addr: Option<IpAddr>,
    try_send_to_lan_addr: bool,
}

#[derive(Clone)]
struct ClientConfigFinalize {
    mtu: usize,
    channel_limit: usize,
    api_addr: SocketAddr,
    tcp_heartbeat_interval_secs: Duration,
    udp_heartbeat_interval_secs: Duration,
    reconnect_interval_secs: Duration,
    udp_socket_recv_buffer_size: Option<usize>,
    udp_socket_send_buffer_size: Option<usize>,
    network_ranges: Vec<NetworkRangeFinalize>,
}

impl TryFrom<ClientConfig> for ClientConfigFinalize {
    type Error = anyhow::Error;

    fn try_from(config: ClientConfig) -> Result<Self> {
        let mut ranges = Vec::with_capacity(config.network_ranges.len());

        for range in config.network_ranges {
            let mode = ProtocolMode::from_str(&range.mode.unwrap_or("UDP_AND_TCP".to_string()))?;

            let lan_ip_addr = match mode {
                ProtocolMode::UdpOnly | ProtocolMode::UdpAndTcp => {
                    let lan_addr = get_interface_addr(
                        range.server_addr
                            .to_socket_addrs()?
                            .next()
                            .ok_or_else(|| anyhow!("Server host not found"))?
                    )?;
                    Some(lan_addr)
                }
                ProtocolMode::TcpOnly => None
            };

            let range_finalize = NetworkRangeFinalize {
                server_addr: range.server_addr.clone(),
                tun: range.tun,
                key: Rc4::new(range.key.as_bytes()),
                mode,
                lan_ip_addr,
                try_send_to_lan_addr: range.try_send_to_lan_addr.unwrap_or(false),
            };
            ranges.push(range_finalize)
        }

        let config_finalize = ClientConfigFinalize {
            mtu: config.mtu.unwrap_or(1450),
            channel_limit: config.channel_limit.unwrap_or(100),
            api_addr: config.api_addr.unwrap_or(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 3030))),
            tcp_heartbeat_interval_secs: Duration::from_secs(config.tcp_heartbeat_interval_secs.unwrap_or(5)),
            udp_heartbeat_interval_secs: Duration::from_secs(config.udp_heartbeat_interval_secs.unwrap_or(5)),
            reconnect_interval_secs: Duration::from_secs(config.reconnect_interval_secs.unwrap_or(3)),
            udp_socket_recv_buffer_size: config.udp_socket_recv_buffer_size,
            udp_socket_send_buffer_size: config.udp_socket_send_buffer_size,
            network_ranges: ranges,
        };
        Ok(config_finalize)
    }
}

fn main() {
    if let Err(e) = launch() {
        error!("Process error -> {:?}", e)
    };
}

fn launch() -> Result<()> {
    logger_init()?;
    let rt = Runtime::new().context("Failed to build tokio runtime")?;

    let res = rt.block_on(async move {
        match load_config().await.context("Failed to load config")? {
            Either::Right(config) => client::start(config).await?,
            Either::Left(config) => server::start(config).await
        }
        Ok(())
    });

    rt.shutdown_background();
    res
}

const INVALID_COMMAND: &str = "Invalid command";

async fn load_config() -> Result<Either<Vec<ServerConfig>, ClientConfigFinalize>> {
    let mut args = env::args();
    args.next();

    let mode = args.next().ok_or_else(|| anyhow!(INVALID_COMMAND))?;
    let config_path = args.next().ok_or_else(|| anyhow!(INVALID_COMMAND))?;
    let config_json = fs::read_to_string(&config_path).await
        .with_context(|| format!("Failed to read config from: {}", config_path))?;

    let config = match mode.as_str() {
        "client" => {
            let client_config = serde_json::from_str::<ClientConfig>(&config_json)
                .context("Failed to parse client config")?;

            Either::Right(ClientConfigFinalize::try_from(client_config)?)
        }
        "server" => {
            let server_config = serde_json::from_str::<Vec<ServerConfig>>(&config_json)
                .context("Failed to pares server config")?;

            Either::Left(server_config)
        }
        _ => Err(anyhow!(INVALID_COMMAND))?
    };
    Ok(config)
}

fn logger_init() -> Result<()> {
    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new("[Console] {d(%Y-%m-%d %H:%M:%S)} - {l} - {m}{n}")))
        .build();

    let config = Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .build(Root::builder().appender("stdout").build(LevelFilter::Info))?;

    log4rs::init_config(config)?;
    Ok(())
}