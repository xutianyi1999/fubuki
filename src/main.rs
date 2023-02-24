#![feature(portable_simd)]
#![feature(split_array)]

#[macro_use]
extern crate log;

use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use log::LevelFilter;
use log4rs::append::console::ConsoleAppender;
use log4rs::config::{Appender, Root};
use log4rs::encode::pattern::PatternEncoder;
use log4rs::Config;
use mimalloc::MiMalloc;
use serde::{de, Deserialize};

use tokio::runtime::Runtime;

use crate::client::Req;
use crate::common::cipher::XorCipher;
use crate::common::net::get_interface_addr;
use crate::common::net::proto::ProtocolMode;

mod client;
mod common;
mod server;
mod tun;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[derive(Deserialize, Clone)]
struct Listener {
    listen_addr: SocketAddr,
    key: String,
}

#[derive(Deserialize, Clone)]
struct ServerConfig {
    channel_limit: Option<usize>,
    tcp_heartbeat_interval_secs: Option<u64>,
    listeners: Vec<Listener>,
}

#[derive(Clone)]
struct ServerConfigFinalize {
    channel_limit: usize,
    tcp_heartbeat_interval: Duration,
    listeners: Vec<Listener>,
}

impl TryFrom<ServerConfig> for ServerConfigFinalize {
    type Error = anyhow::Error;

    fn try_from(config: ServerConfig) -> Result<Self> {
        let config_finalize = Self {
            channel_limit: config.channel_limit.unwrap_or(100),
            tcp_heartbeat_interval: config
                .tcp_heartbeat_interval_secs
                .map(|sec| Duration::from_secs(ternary!(sec > 10, 10, sec)))
                .unwrap_or(Duration::from_secs(5)),
            listeners: {
                for listener in &config.listeners {
                    if listener.listen_addr.ip().is_loopback() {
                        return Err(anyhow!("Listen address cannot be a loopback address"));
                    }
                }
                config.listeners
            },
        };

        Ok(config_finalize)
    }
}

#[derive(Deserialize, Clone)]
struct TunIpAddr {
    ip: Ipv4Addr,
    netmask: Ipv4Addr,
}

#[derive(Deserialize, Clone)]
struct NetworkRange {
    server_addr: String,
    tun: TunIpAddr,
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
    tun_handler_thread_count: Option<usize>,
    udp_handler_thread_count: Option<usize>,
    network_ranges: Vec<NetworkRange>,
}

#[derive(Clone)]
struct NetworkRangeFinalize {
    server_addr: String,
    tun: TunIpAddr,
    key: XorCipher,
    mode: ProtocolMode,
    lan_ip_addr: Option<IpAddr>,
    try_send_to_lan_addr: bool,
}

#[derive(Clone)]
struct ClientConfigFinalize {
    mtu: usize,
    channel_limit: usize,
    api_addr: SocketAddr,
    tcp_heartbeat_interval: Duration,
    udp_heartbeat_interval: Duration,
    reconnect_interval: Duration,
    udp_socket_recv_buffer_size: Option<usize>,
    udp_socket_send_buffer_size: Option<usize>,
    tun_handler_thread_count: usize,
    udp_handler_thread_count: usize,
    network_ranges: Vec<NetworkRangeFinalize>,
}

impl TryFrom<ClientConfig> for ClientConfigFinalize {
    type Error = anyhow::Error;

    fn try_from(config: ClientConfig) -> Result<Self> {
        let mut ranges = Vec::with_capacity(config.network_ranges.len());

        for range in config.network_ranges {
            let mode = ProtocolMode::from_str(range.mode.as_deref().unwrap_or("UDP_AND_TCP"))?;

            let resolve_server_addr = range
                .server_addr
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| anyhow!("Server host not found"))?;

            let lan_ip_addr = match range.lan_ip_addr {
                None => {
                    if mode.udp_support() {
                        let lan_addr = get_interface_addr(resolve_server_addr)?;
                        Some(lan_addr)
                    } else {
                        None
                    }
                }
                Some(addr) => {
                    if addr.is_loopback() {
                        return Err(anyhow!("LAN address cannot be a loopback address"));
                    }

                    if addr.is_unspecified() {
                        return Err(anyhow!("LAN address cannot be unspecified address"));
                    }
                    Some(addr)
                }
            };

            let range_finalize = NetworkRangeFinalize {
                server_addr: {
                    if resolve_server_addr.ip().is_loopback() {
                        return Err(anyhow!("Server address cannot be a loopback address"));
                    }
                    range.server_addr
                },
                tun: range.tun,
                key: XorCipher::new(range.key.as_bytes()),
                mode,
                lan_ip_addr,
                try_send_to_lan_addr: range.try_send_to_lan_addr.unwrap_or(false),
            };
            ranges.push(range_finalize)
        }

        let config_finalize = ClientConfigFinalize {
            mtu: config.mtu.unwrap_or(1462),
            channel_limit: config.channel_limit.unwrap_or(100),
            api_addr: config
                .api_addr
                .unwrap_or_else(|| SocketAddr::from((Ipv4Addr::LOCALHOST, 3030))),
            tcp_heartbeat_interval: config
                .tcp_heartbeat_interval_secs
                .map(|sec| Duration::from_secs(ternary!(sec > 10, 10, sec)))
                .unwrap_or(Duration::from_secs(5)),
            udp_heartbeat_interval: config
                .udp_heartbeat_interval_secs
                .map(|sec| Duration::from_secs(ternary!(sec > 10, 10, sec)))
                .unwrap_or(Duration::from_secs(5)),
            reconnect_interval: Duration::from_secs(config.reconnect_interval_secs.unwrap_or(3)),
            udp_socket_recv_buffer_size: config.udp_socket_recv_buffer_size,
            udp_socket_send_buffer_size: config.udp_socket_send_buffer_size,
            tun_handler_thread_count: config.tun_handler_thread_count.unwrap_or(1),
            udp_handler_thread_count: config.udp_handler_thread_count.unwrap_or(1),
            network_ranges: ranges,
        };
        Ok(config_finalize)
    }
}

const INVALID_COMMAND: &str = "Invalid command";

enum Args {
    Server(Option<String>),
    Client(Option<String>),
    Info(Option<String>),
}

impl Args {
    fn parse() -> Result<Self> {
        let mut args = env::args();
        args.next();
        let mode = args.next().ok_or_else(|| anyhow!(INVALID_COMMAND))?;
        let option = args.next();

        let args = match mode.as_str() {
            "client" => Args::Client(option),
            "server" => Args::Server(option),
            "info" => Args::Info(option),
            _ => return Err(anyhow!(INVALID_COMMAND)),
        };
        Ok(args)
    }
}

fn main() {
    if let Err(e) = launch() {
        error!("Process error -> {:?}", e)
    };
}

macro_rules! block_on {
    ($expr: expr) => {{
        let rt = Runtime::new().context("Failed to build tokio runtime")?;
        let res = rt.block_on($expr);
        rt.shutdown_background();
        res
    }};
}

fn launch() -> Result<()> {
    logger_init().unwrap();

    match Args::parse()? {
        Args::Server(path) => {
            let config: ServerConfig = load_config(path.as_deref().unwrap_or("config.json"))?;

            block_on!(async {
                server::start(ServerConfigFinalize::try_from(config)?).await;
                Ok(())
            })
        }
        Args::Client(path) => {
            let config: ClientConfig = load_config(path.as_deref().unwrap_or("config.json"))?;

            block_on!(client::start(ClientConfigFinalize::try_from(config)?))
        }
        Args::Info(option) => {
            client::call(Req::NodeMap, option.as_deref().unwrap_or("127.0.0.1:3030"))
        }
    }
}

fn load_config<T: de::DeserializeOwned>(path: &str) -> Result<T> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("Failed to read config from: {}", path))?;
    serde_json::from_reader(file).context("Failed to parse config")
}

fn logger_init() -> Result<()> {
    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(
            "[{d(%Y-%m-%d %H:%M:%S)}] {h({l})} {t} - {m}{n}",
        )))
        .build();

    let config = Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .build(
            Root::builder()
                .appender("stdout")
                .build(LevelFilter::from_str(
                    &std::env::var("FUBUKI_LOG").unwrap_or_else(|_| String::from("INFO")),
                )?),
        )?;

    log4rs::init_config(config)?;
    Ok(())
}
