#![feature(portable_simd)]
#![feature(get_mut_unchecked)]
#![feature(impl_trait_in_assoc_type)]
#![feature(sync_unsafe_cell)]

#[macro_use]
extern crate log;

use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use ahash::HashMap;
use anyhow::{anyhow, Result};
use gethostname::gethostname;
use ipnet::Ipv4Net;
use serde::Deserialize;

use crate::common::cipher::{Cipher, CipherEnum, NoOpCipher, XorCipher};
use crate::common::net::get_interface_addr;
use crate::common::net::protocol::{NetProtocol, ProtocolMode, VirtualAddr, SERVER_VIRTUAL_ADDR};

#[macro_use]
pub mod common;
pub mod context;
pub mod node;
pub mod server;
pub mod tun;
pub mod kcp_bridge;

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
mod nat;

#[cfg(feature = "web")]
mod web;
mod routing_table;

#[cfg(feature = "ffi-export")]
mod ffi_export;

pub type Key = CipherEnum;

pub static SHOULD_RESTART: AtomicBool = AtomicBool::new(false);

pub use context::{Context, ExternalContext};
pub use node::{Direction, Interface, InterfaceInfo};
pub use server::GroupInfo;
pub use tun::TunDevice;

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Group {
    name: String,
    listen_addr: SocketAddr,
    key: Option<String>,
    address_range: Ipv4Net,
    flow_control_rules: Option<Vec<(Ipv4Net, byte_unit::Byte)>>,
    allow_udp_relay: Option<bool>,
    allow_tcp_relay: Option<bool>
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
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
pub struct GroupFinalize<K> {
    pub name: String,
    pub listen_addr: SocketAddr,
    pub key: K,
    pub address_range: Ipv4Net,
    pub flow_control_rules: Vec<(Ipv4Net, u64)>,
    pub allow_udp_relay: bool,
    pub allow_tcp_relay: bool
}

#[derive(Clone)]
pub struct ServerConfigFinalize<K> {
    pub channel_limit: usize,
    pub api_addr: SocketAddr,
    pub tcp_heartbeat_interval: Duration,
    pub tcp_heartbeat_continuous_loss: u64,
    pub udp_heartbeat_interval: Duration,
    pub udp_heartbeat_continuous_loss: u64,
    pub udp_heartbeat_continuous_recv: u64,
    pub groups: Vec<GroupFinalize<K>>,
}

impl TryFrom<ServerConfig> for ServerConfigFinalize<CipherEnum> {
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
                        return Err(anyhow!("Invalid group configuration: listen address '{}' cannot be a loopback address. Please provide a public IP address.", group.listen_addr));
                    }

                    if group.address_range.contains(&SERVER_VIRTUAL_ADDR) {
                        warn!("{} is used as a special address, should not be contained in the address range", SERVER_VIRTUAL_ADDR)
                    }

                    let v = GroupFinalize {
                        name: group.name,
                        listen_addr: group.listen_addr,
                        address_range: group.address_range,
                        key: {
                            let key = group.key.as_ref().map(|v| v.as_bytes());
                            match key {
                                None => CipherEnum::NoOpCipher(NoOpCipher{}),
                                Some(k) => CipherEnum::XorCipher(XorCipher::from(k))
                            }
                        },
                        flow_control_rules: group.flow_control_rules
                            .map(|v| v.into_iter().map(|(range, l)| (range, l.as_u64())).collect::<Vec<_>>())
                            .unwrap_or_default(),
                        allow_udp_relay: group.allow_udp_relay.unwrap_or(true),
                        allow_tcp_relay: group.allow_tcp_relay.unwrap_or(true)
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
#[serde(deny_unknown_fields)]
pub struct TunAddr {
    pub ip: VirtualAddr,
    pub netmask: Ipv4Addr,
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct TargetGroup {
    node_name: Option<String>,
    server_addr: String,
    tun_addr: Option<TunAddr>,
    key: Option<String>,
    mode: Option<ProtocolMode>,
    specify_mode: Option<HashMap<VirtualAddr, ProtocolMode>>,
    lan_ip_addr: Option<IpAddr>,
    node_binding: Option<SocketAddr>,
    allowed_ips: Option<Vec<Ipv4Net>>,
    ips: Option<HashMap<VirtualAddr, Vec<Ipv4Net>>>,
    auto_route_selection: Option<bool>,
    use_kcp_session: Option<bool>,
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
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
    external_routing_table: Option<bool>,
    allow_packet_forward: Option<bool>,
    allow_packet_not_in_rules_send_to_kernel: Option<bool>,
    enable_hook: Option<bool>,
    socket_bind_device: Option<String>,
    #[cfg(feature = "cross-nat")]
    cross_nat: Option<bool>,
    groups: Vec<TargetGroup>,
    features: Option<NodeConfigFeature>,
}

#[derive(Deserialize, Clone)]
pub struct NodeConfigFeature {
    disable_hosts_operation: Option<bool>,
    disable_signal_handling: Option<bool>,
    disable_route_operation: Option<bool>,
    disable_api_server: Option<bool>,
}

#[derive(Clone)]
pub struct TargetGroupFinalize<K> {
    pub node_name: String,
    pub server_addr: String,
    pub tun_addr: Option<TunAddr>,
    pub key: K,
    pub mode: ProtocolMode,
    pub specify_mode: HashMap<VirtualAddr, ProtocolMode>,
    pub lan_ip_addr: Option<IpAddr>,
    pub node_binding: Option<SocketAddr>,
    pub allowed_ips: Vec<Ipv4Net>,
    pub ips: HashMap<VirtualAddr, Vec<Ipv4Net>>,
    pub auto_route_selection: bool,
    pub use_kcp_session: bool,
}

#[derive(Clone)]
pub struct NodeConfigFinalize<K> {
    pub mtu: usize,
    pub channel_limit: usize,
    pub api_addr: SocketAddr,
    pub tcp_heartbeat_interval: Duration,
    pub udp_heartbeat_interval: Duration,
    pub tcp_heartbeat_continuous_loss: u64,
    pub udp_heartbeat_continuous_loss: u64,
    pub udp_heartbeat_continuous_recv: u64,
    pub reconnect_interval: Duration,
    pub udp_socket_recv_buffer_size: Option<usize>,
    pub udp_socket_send_buffer_size: Option<usize>,
    pub external_routing_table: bool,
    pub allow_packet_forward: bool,
    pub allow_packet_not_in_rules_send_to_kernel: bool,
    pub enable_hook: bool,
    pub socket_bind_device: Option<String>,
    #[cfg(feature = "cross-nat")]
    pub cross_nat: bool,
    pub groups: Vec<TargetGroupFinalize<K>>,
    pub features: NodeConfigFeatureFinalize,
}

#[derive(Clone)]
pub struct NodeConfigFeatureFinalize {
    #[allow(unused)]
    pub disable_hosts_operation: bool,
    pub disable_signal_handling: bool,
    pub disable_route_operation: bool,
    pub disable_api_server: bool,
}

impl TryFrom<NodeConfig> for NodeConfigFinalize<CipherEnum> {
    type Error = anyhow::Error;

    fn try_from(config: NodeConfig) -> Result<Self> {
        let mut list = Vec::with_capacity(config.groups.len());
        let mut use_ipv6 = false;
        let mut use_udp = false;
        #[allow(unused)]
        let mut use_gateway = false;

        for group in config.groups {
            let mode = group.mode.unwrap_or_default();

            if mode.p2p.contains(&NetProtocol::TCP) {
                return Err(anyhow!("Invalid group configuration: P2P connections currently only support UDP protocol. TCP is not supported."))
            }

            let resolve_server_addr = group
                .server_addr
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| anyhow!("{} lookup failed", group.server_addr))?;

            let lan_ip_addr = match group.lan_ip_addr {
                None => {
                    get_interface_addr(resolve_server_addr)?
                }
                Some(addr) => {
                    if addr.is_loopback() {
                        return Err(anyhow!("Invalid group configuration: LAN address '{}' cannot be a loopback address. Please specify a valid LAN IP.", addr));
                    }

                    if addr.is_unspecified() {
                        return Err(anyhow!("Invalid group configuration: LAN address '{}' cannot be an unspecified address. Please specify a valid LAN IP.", addr));
                    }
                    addr
                }
            };

            if let Some(map) = group.ips.as_ref() {
                for items in map.values() {
                    for x in items {
                        use_gateway |= *x == Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).unwrap();
                    }
                }
            }

            let group_use_udp = mode.is_use_udp() || group.use_kcp_session.unwrap_or(false);

            if group_use_udp {
                use_ipv6 |= lan_ip_addr.is_ipv6();
                use_udp = true;
            };

            let group_finalize = TargetGroupFinalize {
                node_name: {
                    match group.node_name {
                        None => {
                            gethostname()
                                .to_str()
                                .ok_or_else(|| anyhow!("Failed to resolve hostname for node_name. Ensure the system hostname is properly configured."))?
                                .to_string()
                        }
                        Some(v) => v
                    }
                },
                server_addr: {
                    if resolve_server_addr.ip().is_loopback() {
                        return Err(anyhow!("Invalid group configuration: server address '{}' cannot be a loopback address. Please provide a public IP address.", resolve_server_addr));
                    }
                    group.server_addr
                },
                tun_addr: group.tun_addr,
                key: {
                    let key = group.key.as_ref().map(|v| v.as_bytes());
                    match key {
                        None => CipherEnum::NoOpCipher(NoOpCipher{}),
                        Some(k) => CipherEnum::XorCipher(XorCipher::from(k))
                    }
                },
                mode,
                specify_mode: group.specify_mode.unwrap_or_default(),
                lan_ip_addr: ternary!(group_use_udp, Some(lan_ip_addr), None),
                node_binding: group.node_binding,
                allowed_ips: group.allowed_ips.unwrap_or_default(),
                ips: group.ips.unwrap_or_default(),
                auto_route_selection: group.auto_route_selection.unwrap_or(false),
                use_kcp_session: group.use_kcp_session.unwrap_or(false),
            };
            list.push(group_finalize)
        }

        let config_finalize = NodeConfigFinalize {
            mtu: config.mtu.unwrap_or({
                if use_udp {
                    if use_ipv6 {
                        1424
                    } else {
                        1444
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
            external_routing_table: config.external_routing_table.unwrap_or(false),
            allow_packet_forward: config.allow_packet_forward.unwrap_or(true),
            allow_packet_not_in_rules_send_to_kernel: config.allow_packet_not_in_rules_send_to_kernel.unwrap_or(false),
            enable_hook: config.enable_hook.unwrap_or(false),
            #[cfg(feature = "cross-nat")]
            cross_nat: config.cross_nat.unwrap_or_else(|| {
                #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
                if nat::check_available() {
                    false
                } else {
                    warn!("native NAT not available, falling back to cross-nat");
                    true
                }
                
                #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
                {
                    true
                }
            }),
            socket_bind_device: {
                #[allow(unused_mut)]
                let mut bind = config.socket_bind_device;

                #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
                if bind.is_none() && use_gateway {
                    let lan = get_interface_addr(SocketAddr::new([1, 1, 1, 1].into(), 53))?;
                    let if_name = crate::common::net::find_interface(lan)?;
                    bind = Some(if_name);
                }
                bind
            },
            features: {
                let features = config.features.as_ref();

                NodeConfigFeatureFinalize {
                    disable_hosts_operation: features.and_then(|f| f.disable_hosts_operation).unwrap_or(false),
                    disable_signal_handling: features.and_then(|f| f.disable_signal_handling).unwrap_or(false),
                    disable_route_operation: features.and_then(|f| f.disable_route_operation).unwrap_or(false),
                    disable_api_server: features.and_then(|f| f.disable_api_server).unwrap_or(false),
                }
            },
        };
        Ok(config_finalize)
    }
}

#[cfg(feature = "ffi-export")]
pub(crate) fn logger_init() -> Result<()> {
    #[cfg(target_os = "android")]
    {
        use std::str::FromStr;
        use log::LevelFilter;
        android_logger::init_once(
            android_logger::Config::default().with_max_level(LevelFilter::from_str(
                std::env::var("FUBUKI_LOG").as_deref().unwrap_or("INFO"),
            )?),
        );
        Ok(())
    }

    #[cfg(not(target_os = "android"))]
    {
        use std::str::FromStr;
        use log::LevelFilter;
        use log4rs::append::console::ConsoleAppender;
        use log4rs::config::{Appender, Root};
        use log4rs::encode::pattern::PatternEncoder;

        fn init() -> Result<()> {
            let log_level = LevelFilter::from_str(
                std::env::var("FUBUKI_LOG").as_deref().unwrap_or("INFO"),
            )?;

            let pattern = if log_level >= LevelFilter::Debug {
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
                        .build(log_level),
                )?;

            log4rs::init_config(config)?;
            Ok(())
        }

        static LOGGER_INIT: std::sync::Once = std::sync::Once::new();
        LOGGER_INIT.call_once(|| {
            init().expect("Critical error: Logger initialization failed. Please check log configuration.");
        });
        Ok(())
    }
}
