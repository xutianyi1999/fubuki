#![feature(portable_simd)]
#![feature(trait_alias)]
#![feature(type_alias_impl_trait)]
#![feature(split_array)]
#![feature(new_uninit)]
#![feature(maybe_uninit_slice)]
#![feature(get_mut_unchecked)]

#[macro_use]
extern crate log;

use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::process::ExitCode;
use std::str::FromStr;
use std::time::Duration;

use ahash::HashMap;
use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use human_panic::setup_panic;
use ipnet::Ipv4Net;
use log4rs::append::console::ConsoleAppender;
use log4rs::config::{Appender, Root};
use log4rs::encode::pattern::PatternEncoder;
use log::LevelFilter;
use mimalloc::MiMalloc;
use serde::{de, Deserialize};
use tokio::runtime::Runtime;
use crate::client::info;

use crate::common::cipher::{Cipher, XorCipher};
use crate::common::net::get_interface_addr;
use crate::common::net::protocol::{NetProtocol, ProtocolMode, VirtualAddr};

mod client;
mod common;
mod server;
mod tun;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

type Key = XorCipher;

#[derive(Deserialize, Clone)]
struct Group {
    name: String,
    listen_addr: SocketAddr,
    key: String,
    address_range: Ipv4Net,
}

#[derive(Deserialize, Clone)]
struct ServerConfig {
    channel_limit: Option<usize>,
    tcp_heartbeat_interval_secs: Option<u64>,
    tcp_heartbeat_continuous_loss: Option<u64>,
    udp_heartbeat_interval_secs: Option<u64>,
    udp_heartbeat_continuous_loss: Option<u64>,
    udp_heartbeat_continuous_recv: Option<u64>,
    groups: Vec<Group>,
}

#[derive(Clone)]
struct GroupFinalize<K> {
    name: String,
    listen_addr: SocketAddr,
    key: K,
    address_range: Ipv4Net,
}

#[derive(Clone)]
struct ServerConfigFinalize<K> {
    channel_limit: usize,
    tcp_heartbeat_interval: Duration,
    tcp_heartbeat_continuous_loss: u64,
    udp_heartbeat_interval: Duration,
    udp_heartbeat_continuous_loss: u64,
    udp_heartbeat_continuous_recv: u64,
    groups: Vec<GroupFinalize<K>>,
}

trait InnerTryFrom<'a> = TryFrom<&'a [u8]> where <Self as TryFrom<&'a [u8]>>::Error: Error + Send + Sync + 'static;

impl<K> TryFrom<ServerConfig> for ServerConfigFinalize<K>
where
    for<'a> K: InnerTryFrom<'a>,
{
    type Error = anyhow::Error;

    fn try_from(config: ServerConfig) -> std::result::Result<Self, Self::Error> {
        let config_finalize = Self {
            channel_limit: config.channel_limit.unwrap_or(100),
            tcp_heartbeat_interval: config
                .tcp_heartbeat_interval_secs
                .map(Duration::from_secs)
                .unwrap_or(Duration::from_secs(5)),
            tcp_heartbeat_continuous_loss: config.tcp_heartbeat_continuous_loss.unwrap_or(5),
            udp_heartbeat_interval: config
                .udp_heartbeat_interval_secs
                .map(Duration::from_secs)
                .unwrap_or(Duration::from_secs(5)),
            udp_heartbeat_continuous_loss: config.udp_heartbeat_continuous_loss.unwrap_or(5),
            udp_heartbeat_continuous_recv: config.udp_heartbeat_continuous_recv.unwrap_or(3),
            groups: {
                let mut list = Vec::with_capacity(config.groups.len());

                for group in config.groups {
                    if group.listen_addr.ip().is_loopback() {
                        return Err(anyhow!("Listen address can't be a loopback address"));
                    }

                    let v = GroupFinalize {
                        name: group.name,
                        listen_addr: group.listen_addr,
                        address_range: group.address_range,
                        key: K::try_from(group.key.as_bytes())?,
                    };
                    list.push(v);
                }
                list
            },
        };

        Ok(config_finalize)
    }
}

#[derive(Deserialize, Clone)]
struct TunAddr {
    ip: VirtualAddr,
    netmask: Ipv4Addr,
}

#[derive(Deserialize, Clone)]
struct TargetGroup {
    node_name: String,
    server_addr: String,
    tun_addr: Option<TunAddr>,
    key: String,
    mode: Option<ProtocolMode>,
    lan_ip_addr: Option<IpAddr>,
    ips: Option<HashMap<VirtualAddr, Vec<Ipv4Net>>>,
}

#[derive(Deserialize, Clone)]
struct ClientConfig {
    mtu: Option<usize>,
    channel_limit: Option<usize>,
    api_addr: Option<SocketAddr>,
    tcp_heartbeat_interval_secs: Option<u64>,
    udp_heartbeat_interval_secs: Option<u64>,
    tcp_heartbeat_continuous_loss: Option<u64>,
    udp_heartbeat_continuous_loss: Option<u64>,
    udp_heartbeat_continuous_recv: Option<u64>,
    reconnect_interval_secs: Option<u64>,
    udp_socket_recv_buffer_size: Option<usize>,
    udp_socket_send_buffer_size: Option<usize>,
    allowed_ips: Option<Vec<Ipv4Net>>,
    groups: Vec<TargetGroup>,
}

#[derive(Clone)]
struct TargetGroupFinalize<K> {
    node_name: String,
    server_addr: String,
    tun_addr: Option<TunAddr>,
    key: K,
    mode: ProtocolMode,
    lan_ip_addr: Option<IpAddr>,
    // todo check ips and tun network conflicts
    ips: HashMap<VirtualAddr, Vec<Ipv4Net>>,
}

#[derive(Clone)]
pub struct ClientConfigFinalize<K> {
    mtu: usize,
    channel_limit: usize,
    api_addr: SocketAddr,
    tcp_heartbeat_interval: Duration,
    udp_heartbeat_interval: Duration,
    tcp_heartbeat_continuous_loss: u64,
    udp_heartbeat_continuous_loss: u64,
    udp_heartbeat_continuous_recv: u64,
    reconnect_interval: Duration,
    udp_socket_recv_buffer_size: Option<usize>,
    udp_socket_send_buffer_size: Option<usize>,
    // todo consider into the group
    allowed_ips: Vec<Ipv4Net>,
    groups: Vec<TargetGroupFinalize<K>>,
}

impl<K: Clone> TryFrom<ClientConfig> for ClientConfigFinalize<K>
where
    for<'a> K: InnerTryFrom<'a>,
{
    type Error = anyhow::Error;

    fn try_from(config: ClientConfig) -> Result<Self> {
        let mut list = Vec::with_capacity(config.groups.len());

        for group in config.groups {
            let mode = group.mode.unwrap_or_default();

            if mode.direct.contains(&NetProtocol::TCP) {
                return Err(anyhow!("Direct only support UDP"))
            }

            let resolve_server_addr = group
                .server_addr
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| anyhow!("Server host not found"))?;

            let lan_ip_addr = match group.lan_ip_addr {
                None => {
                    if mode.is_use_udp() {
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

            let group_finalize = TargetGroupFinalize {
                node_name: group.node_name,
                server_addr: {
                    if resolve_server_addr.ip().is_loopback() {
                        return Err(anyhow!("Server address cannot be a loopback address"));
                    }
                    group.server_addr
                },
                tun_addr: group.tun_addr,
                key: K::try_from(group.key.as_bytes())?,
                mode,
                lan_ip_addr,
                ips: group.ips.unwrap_or_default()
            };
            list.push(group_finalize)
        }

        let config_finalize = ClientConfigFinalize {
            // 1500 - 8byte PPPOE - 20byte IPV4 HEADER - 8byte UDP HEADER - 2byte UDP MSG HEADER - 4byte UDP MSG RELAY IP ADDRESS
            mtu: config.mtu.unwrap_or(1458),
            channel_limit: config.channel_limit.unwrap_or(100),
            api_addr: config
                .api_addr
                .unwrap_or_else(|| SocketAddr::from((Ipv4Addr::LOCALHOST, 3030))),
            tcp_heartbeat_interval: config
                .tcp_heartbeat_interval_secs
                .map(Duration::from_secs)
                .unwrap_or(Duration::from_secs(5)),
            udp_heartbeat_interval: config
                .udp_heartbeat_interval_secs
                .map(Duration::from_secs)
                .unwrap_or(Duration::from_secs(5)),
            tcp_heartbeat_continuous_loss: config.tcp_heartbeat_continuous_loss.unwrap_or(5),
            udp_heartbeat_continuous_loss: config.udp_heartbeat_continuous_loss.unwrap_or(5),
            udp_heartbeat_continuous_recv: config.udp_heartbeat_continuous_recv.unwrap_or(3),
            reconnect_interval: Duration::from_secs(config.reconnect_interval_secs.unwrap_or(3)),
            udp_socket_recv_buffer_size: config.udp_socket_recv_buffer_size,
            udp_socket_send_buffer_size: config.udp_socket_send_buffer_size,
            allowed_ips: config.allowed_ips.unwrap_or_default(),
            groups: list,
        };
        Ok(config_finalize)
    }
}

#[derive(Clone, Copy, Subcommand)]
enum NodeInfoType {
    Interface,
    NodeMap {
        interface_id: usize
    }
}

#[derive(Subcommand)]
enum NodeCmd {
    Daemon {
        config_path: String
    },
    Info {
        #[arg(short, long, default_value = "127.0.0.1:3030")]
        api: String,

        #[command(subcommand)]
        info_type: NodeInfoType,
    }
}

#[derive(Subcommand)]
enum ServerCmd {
    Daemon {
        config_path: String
    },
    Info {
        #[arg(short, long, default_value = "127.0.0.1:3030")]
        api: String,
    }
}

#[derive(Parser)]
#[command(version)]
enum Args {
    Server {
        #[command(subcommand)]
        cmd: ServerCmd
    },
    Node {
        #[command(subcommand)]
        cmd: NodeCmd
    },
}

fn load_config<T: de::DeserializeOwned>(path: &str) -> Result<T> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("Failed to read config from: {}", path))?;

    serde_json::from_reader(file).context("Failed to parse config")
}

fn logger_init() -> Result<()> {
    let pattern = if cfg!(debug_assertions) {
        "[{d(%Y-%m-%d %H:%M:%S)}] {h({l})} {f}:{L} - {m}{n}"
    } else {
        "[{d(%Y-%m-%d %H:%M:%S)}] {h({l})} {t} - {m}{n}"
    };

    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(pattern)))
        .build();

    let config = log4rs::Config::builder()
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

fn launch(args: Args) -> Result<()> {
    logger_init()?;

    match args {
        Args::Server { cmd } => {
            match cmd {
                ServerCmd::Daemon { config_path } => {
                    let t: ServerConfig = load_config(&config_path)?;
                    let config: ServerConfigFinalize<Key> = ServerConfigFinalize::try_from(t)?;
                    let rt = Runtime::new()?;
                    rt.block_on(server::start(config));
                }
                ServerCmd::Info { .. } => {}
            }
        }
        Args::Node { cmd } => {
            match cmd {
                NodeCmd::Daemon { config_path } => {
                    let config: ClientConfig = load_config(&config_path)?;
                    let c: ClientConfigFinalize<Key> = ClientConfigFinalize::try_from(config)?;
                    let rt = Runtime::new()?;
                    rt.block_on(client::start(c))?;
                }
                NodeCmd::Info { api, info_type } => {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?;

                    rt.block_on(info(&api, info_type))?;
                }
            }
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    setup_panic!();

    match launch(Args::parse()) {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{:?}", e);
            ExitCode::FAILURE
        }
    }
}
