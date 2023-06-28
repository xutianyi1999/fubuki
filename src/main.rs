#![feature(portable_simd)]
#![feature(trait_alias)]
#![feature(split_array)]
#![feature(new_uninit)]
#![feature(maybe_uninit_slice)]
#![feature(get_mut_unchecked)]
#![feature(impl_trait_in_assoc_type)]
#![feature(lazy_cell)]

#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

#[macro_use]
extern crate log;

use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;
use std::time::Duration;

use ahash::HashMap;
use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use gethostname::gethostname;
use human_panic::setup_panic;
use ipnet::Ipv4Net;
use log4rs::append::console::ConsoleAppender;
use log4rs::config::{Appender, Root};
use log4rs::encode::pattern::PatternEncoder;
use log::LevelFilter;
use mimalloc::MiMalloc;
use serde::{de, Deserialize};
use tokio::runtime::Runtime;

use crate::common::cipher::{Cipher, XorCipher};
use crate::common::net::get_interface_addr;
use crate::common::net::protocol::{NetProtocol, ProtocolMode, SERVER_VIRTUAL_ADDR, VirtualAddr};

mod node;
mod common;
mod server;
mod tun;

#[cfg_attr(target_os = "windows", path = "nat/windows.rs")]
#[cfg_attr(target_os = "linux", path = "nat/linux.rs")]
#[cfg_attr(target_os = "macos", path = "nat/macos.rs")]
mod nat;

#[cfg(feature = "web")]
mod web;

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
    api_addr: Option<SocketAddr>,
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
    api_addr: SocketAddr,
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
            api_addr: config
                .api_addr
                .unwrap_or_else(|| SocketAddr::from((Ipv4Addr::LOCALHOST, 3031))),
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
                        return Err(anyhow!("listen address can't be a loopback address"));
                    }

                    if group.address_range.contains(&SERVER_VIRTUAL_ADDR) {
                        warn!("{} is used as a special address, should not be contained in the address range", SERVER_VIRTUAL_ADDR)
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
    node_name: Option<String>,
    server_addr: String,
    tun_addr: Option<TunAddr>,
    key: String,
    mode: Option<ProtocolMode>,
    lan_ip_addr: Option<IpAddr>,
    allowed_ips: Option<Vec<Ipv4Net>>,
    ips: Option<HashMap<VirtualAddr, Vec<Ipv4Net>>>,
}

#[derive(Deserialize, Clone)]
struct NodeConfig {
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
    allowed_ips: Vec<Ipv4Net>,
    ips: HashMap<VirtualAddr, Vec<Ipv4Net>>,
}

#[derive(Clone)]
pub struct NodeConfigFinalize<K> {
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
    groups: Vec<TargetGroupFinalize<K>>,
}

impl<K: Clone> TryFrom<NodeConfig> for NodeConfigFinalize<K>
where
    for<'a> K: InnerTryFrom<'a>,
{
    type Error = anyhow::Error;

    fn try_from(config: NodeConfig) -> Result<Self> {
        let mut list = Vec::with_capacity(config.groups.len());
        let mut use_ipv6 = false;
        let mut use_udp = false;

        for group in config.groups {
            let mode = group.mode.unwrap_or_default();

            if mode.p2p.contains(&NetProtocol::TCP) {
                return Err(anyhow!("p2p only support udp protocol"))
            }

            let resolve_server_addr = group
                .server_addr
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| anyhow!("{} lookup failed", group.server_addr))?;

            let lan_ip_addr = if mode.is_use_udp() {
                let lan_ip_addr = match group.lan_ip_addr {
                    None => {
                        get_interface_addr(resolve_server_addr)?
                    }
                    Some(addr) => {
                        if addr.is_loopback() {
                            return Err(anyhow!("lan address cannot be a loopback address"));
                        }

                        if addr.is_unspecified() {
                            return Err(anyhow!("lan address cannot be unspecified address"));
                        }
                        addr
                    }
                };

                if lan_ip_addr.is_ipv6() {
                    use_ipv6 = true;
                }

                use_udp = true;
                Some(lan_ip_addr)
            } else {
                None
            };

            let group_finalize = TargetGroupFinalize {
                node_name: {
                    match group.node_name {
                        None => {
                            gethostname()
                                .to_str()
                                .ok_or_else(|| anyhow!("unable to resolve hostname"))?
                                .to_string()
                        }
                        Some(v) => v
                    }
                },
                server_addr: {
                    if resolve_server_addr.ip().is_loopback() {
                        return Err(anyhow!("server address cannot be a loopback address"));
                    }
                    group.server_addr
                },
                tun_addr: group.tun_addr,
                key: K::try_from(group.key.as_bytes())?,
                mode,
                lan_ip_addr,
                allowed_ips: group.allowed_ips.unwrap_or_default(),
                ips: group.ips.unwrap_or_default()
            };
            list.push(group_finalize)
        }

        let config_finalize = NodeConfigFinalize {
            mtu: config.mtu.unwrap_or_else(|| {
                if use_udp {
                    if use_ipv6 {
                        // 1500 - 8byte 802.3 SNAP - 4byte 802.1Q VLAN - 8byte PPPOE - 40byte IPV6 HEADER - 8byte UDP HEADER - 2byte UDP MSG HEADER - 4byte UDP MSG RELAY IP ADDRESS
                        1426
                    } else {
                        // 1500 - 8byte 802.3 SNAP - 4byte 802.1Q VLAN - 8byte PPPOE - 20byte IPV4 HEADER - 8byte UDP HEADER - 2byte UDP MSG HEADER - 4byte UDP MSG RELAY IP ADDRESS
                        1446
                    }
                } else {
                    1500
                }
            }),
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
            groups: list,
        };
        Ok(config_finalize)
    }
}

#[derive(Clone, Copy, Subcommand)]
enum NodeInfoType {
    /// query node interface
    Interface {
        /// show more data for the specified interface
        #[arg(short, long)]
        index: Option<usize>,
    },
    /// query all peer nodes of a specified interface
    NodeMap {
        /// interface index
        interface_index: usize,

        /// show more data for the specified node
        #[arg(short, long)]
        node_ip: Option<VirtualAddr>,
    }
}

#[derive(Subcommand)]
enum NodeCmd {
    /// start the node process
    Daemon {
        /// configuration file path
        config_path: PathBuf
    },
    /// query the current state of the node
    Info {
        /// api address of the node
        #[arg(short, long, default_value = "127.0.0.1:3030")]
        api: String,

        /// query type
        #[command(subcommand)]
        info_type: NodeInfoType,
    }
}

#[derive(Clone, Subcommand)]
enum ServerInfoType {
    /// query server group
    Group,
    /// query the node map of the specified group
    NodeMap {
        /// group name
        group_name: String,

        /// show more data for the specified node
        #[arg(short, long)]
        node_ip: Option<VirtualAddr>,
    }
}

#[derive(Subcommand)]
enum ServerCmd {
    /// start the server process
    Daemon {
        /// configuration file path
        config_path: PathBuf
    },
    /// query the current state of the server
    Info {
        /// api address of the server
        #[arg(short, long, default_value = "127.0.0.1:3031")]
        api: String,

        /// query type
        #[command(subcommand)]
        info_type: ServerInfoType,
    }
}

#[derive(Parser)]
#[command(version)]
enum Args {
    /// coordinator and data relay server
    Server {
        #[command(subcommand)]
        cmd: ServerCmd
    },
    /// fubuki node
    Node {
        #[command(subcommand)]
        cmd: NodeCmd
    },
}

fn load_config<T: de::DeserializeOwned>(path: &Path) -> Result<T> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("failed to read config from: {}", path.to_string_lossy()))?;

    serde_json::from_reader(file).context("failed to parse config")
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
                    rt.block_on(server::start(config))?;
                }
                ServerCmd::Info { api, info_type } => {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?;

                    rt.block_on(server::info(&api, info_type))?;
                }
            }
        }
        Args::Node { cmd } => {
            match cmd {
                NodeCmd::Daemon { config_path } => {
                    let config: NodeConfig = load_config(&config_path)?;
                    let c: NodeConfigFinalize<Key> = NodeConfigFinalize::try_from(config)?;
                    let rt = Runtime::new()?;
                    rt.block_on(node::start(c))?;
                }
                NodeCmd::Info { api, info_type } => {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?;

                    rt.block_on(node::info(&api, info_type))?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(not(feature = "gui"))]
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

#[cfg(feature = "gui")]
fn main() -> ExitCode {
    setup_panic!();

    let mut settings = klask::Settings::default();

    if let Ok(path) = std::env::var("FUBUKI_GUI_FONT_PATH") {
        let font = match std::fs::read(path) {
            Ok(font) => font,
            Err(e) => {
                eprintln!("read font data error: {:?}", e);
                return ExitCode::FAILURE;
            }
        };
        settings.custom_font = Some(std::borrow::Cow::Owned(font));
    }

    klask::run_derived::<Args, _>(settings, |args| {
        if let Err(e) = launch(args) {
            eprintln!("{:?}", e);
        }
    });

    ExitCode::SUCCESS
}
