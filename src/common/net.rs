use std::fmt::{Display, Formatter};
use std::io;
use std::io::Result;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::Range;
use std::time::Instant;
use chrono::Utc;
use crossbeam_utils::atomic::AtomicCell;
use ipnet::Ipv4Net;
use parking_lot::RwLock;

use serde::{Deserialize, Serialize};
use socket2::TcpKeepalive;
use tokio::time::Duration;

use crate::common::net::protocol::Seq;

pub trait SocketExt {
    fn set_keepalive(&self) -> Result<()>;

    fn set_recv_buffer_size(&self, size: usize) -> Result<()>;

    fn set_send_buffer_size(&self, size: usize) -> Result<()>;

    fn bind_device(&self, interface: &str, ipv6: bool) -> Result<()>;
}

const TCP_KEEPALIVE: TcpKeepalive = TcpKeepalive::new().with_time(Duration::from_secs(120));

#[cfg(target_os = "linux")]
fn bind_device<T: std::os::unix::io::AsFd>(
    socket: &T,
    interface: &str,
    _ipv6: bool
) -> Result<()> {
    let socket = socket2::SockRef::from(socket);
    socket.bind_device(Some(interface.as_bytes()))
}

#[cfg(target_os = "macos")]
fn bind_device<T: std::os::unix::io::AsFd>(
    socket: &T,
    interface: &str,
    ipv6: bool
) -> Result<()> {
    use std::num::NonZeroU32;

    let socket = socket2::SockRef::from(socket);

    let index = netconfig::Interface::try_from_name(interface)
        .and_then(|i| i.index())
        .map_err(|e| std::io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    if ipv6 {
        socket.bind_device_by_index_v6(NonZeroU32::new(index))
    } else {
        socket.bind_device_by_index_v4(NonZeroU32::new(index))
    }
}

#[cfg(windows)]
fn bind_device<T: std::os::windows::io::AsSocket>(
    socket: &T,
    interface: &str,
    ipv6: bool,
) -> Result<()> {
    use netconfig::sys::InterfaceExt;
    use std::os::windows::io::AsRawSocket;

    let index = netconfig::Interface::try_from_alias(interface)
        .and_then(|i| i.index())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    let raw = socket.as_socket().as_raw_socket();

    unsafe {
        let code = if ipv6 {
            windows::Win32::Networking::WinSock::setsockopt(
                windows::Win32::Networking::WinSock::SOCKET(raw as usize),
                windows::Win32::Networking::WinSock::IPPROTO_IPV6.0,
                windows::Win32::Networking::WinSock::IPV6_UNICAST_IF,
                Some(&index.to_be_bytes()),
            )
        } else {
            windows::Win32::Networking::WinSock::setsockopt(
                windows::Win32::Networking::WinSock::SOCKET(raw as usize),
                windows::Win32::Networking::WinSock::IPPROTO_IP.0,
                windows::Win32::Networking::WinSock::IP_UNICAST_IF,
                Some(&index.to_be_bytes()),
            )
        };

        if code != 0 {
            return Err(io::Error::last_os_error());
        }
    };

    Ok(())
}

macro_rules! build_socket_ext {
    ($type:path) => {
        impl<T: $type> SocketExt for T {
            fn set_keepalive(&self) -> Result<()> {
                let sock_ref = socket2::SockRef::from(self);
                sock_ref.set_tcp_keepalive(&TCP_KEEPALIVE)
            }

            fn set_recv_buffer_size(&self, size: usize) -> Result<()> {
                let sock_ref = socket2::SockRef::from(self);
                sock_ref.set_recv_buffer_size(size)
            }

            fn set_send_buffer_size(&self, size: usize) -> Result<()> {
                let sock_ref = socket2::SockRef::from(self);
                sock_ref.set_send_buffer_size(size)
            }

            fn bind_device(&self, interface: &str, ipv6: bool) -> Result<()> {
                bind_device(self, interface, ipv6)
            }
        }
    };
}

#[cfg(windows)]
build_socket_ext!(std::os::windows::io::AsSocket);

#[cfg(unix)]
build_socket_ext!(std::os::unix::io::AsFd);

macro_rules! get {
    ($slice: expr, $index: expr, $error_msg: expr) => {
        $slice
            .get($index)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, $error_msg))?
    };
    ($slice: expr, $index: expr) => {
        get!($slice, $index, "decode error")
    };
}

const SRC_ADDR: Range<usize> = 12..16;
const DST_ADDR: Range<usize> = 16..20;

pub fn get_ip_dst_addr(ip_packet: &[u8]) -> Result<Ipv4Addr> {
    let mut buff = [0u8; 4];
    buff.copy_from_slice(get!(
        ip_packet,
        DST_ADDR,
        "get packet source address failed"
    ));
    Ok(Ipv4Addr::from(buff))
}

pub fn get_ip_src_addr(ip_packet: &[u8]) -> Result<Ipv4Addr> {
    let mut buff = [0u8; 4];
    buff.copy_from_slice(get!(
        ip_packet,
        SRC_ADDR,
        "get packet destination address failed"
    ));
    Ok(Ipv4Addr::from(buff))
}

pub fn get_interface_addr(dest_addr: SocketAddr) -> Result<IpAddr> {
    let bind_addr = match dest_addr {
        SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };

    let socket = std::net::UdpSocket::bind((bind_addr, 0))?;
    socket.connect(dest_addr)?;
    let addr = socket.local_addr()?;
    Ok(addr.ip())
}

#[derive(Serialize, Deserialize, Clone, Copy, Eq, PartialEq)]
pub enum UdpStatus {
    Available { dst_addr: SocketAddr },
    Unavailable,
}

impl Display for UdpStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            UdpStatus::Available { dst_addr } => write!(f, "Available({})", dst_addr),
            UdpStatus::Unavailable => write!(f, "Unavailable"),
        }
    }
}

#[derive(Clone)]
pub struct HeartbeatCache {
    pub seq: Seq,
    pub send_time: Instant,
    pub is_reply: bool,
    pub last_elapsed: Option<Duration>,
    pub send_count: u64,
    pub packet_continuous_loss_count: u64,
    pub packet_continuous_recv_count: u64,
    pub packet_loss_count: u64,
    pub is_send: bool,
}

impl HeartbeatCache {
    pub fn new() -> Self {
        HeartbeatCache {
            seq: 0,
            send_time: Instant::now(),
            is_reply: false,
            last_elapsed: None,
            send_count: 0,
            packet_continuous_loss_count: 0,
            packet_continuous_recv_count: 0,
            packet_loss_count: 0,
            is_send: false,
        }
    }

    pub fn reply(&mut self, reply_seq: Seq) -> Option<Duration> {
        if self.seq == reply_seq {
            self.packet_continuous_loss_count = 0;
            self.packet_continuous_recv_count += 1;

            let elapsed = Some(self.send_time.elapsed());
            self.is_reply = true;
            self.last_elapsed = elapsed;
            elapsed
        } else {
            None
        }
    }

    pub fn check(&mut self) {
        if self.is_send && !self.is_reply {
            self.packet_continuous_recv_count = 0;
            self.packet_loss_count += 1;
            self.packet_continuous_loss_count += 1;
        }
        self.is_send = false;
    }

    pub fn ping(&mut self) {
        self.is_send = true;
        self.is_reply = false;
        self.send_time = Instant::now();
        self.seq = self.seq.overflowing_add(1).0;
        self.send_count += 1;
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct HeartbeatInfo {
    pub elapsed: Option<Duration>,
    pub send_count: u64,
    pub packet_continuous_loss_count: u64,
    pub packet_continuous_recv_count: u64,
    pub packet_loss_count: u64,
}

impl From<&HeartbeatCache> for HeartbeatInfo {
    fn from(value: &HeartbeatCache) -> Self {
        HeartbeatInfo {
            elapsed: value.last_elapsed,
            send_count: value.send_count,
            packet_continuous_loss_count: value.packet_continuous_loss_count,
            packet_continuous_recv_count: value.packet_continuous_recv_count,
            packet_loss_count: value.packet_loss_count,
        }
    }
}

pub struct FlowControl {
    // flow rule, (address range, byte/s), example: { "192.168.8.0/24": "2048", "192.168.8.10/32": "1024" }
    rule: Vec<(Ipv4Net, u64)>,
    // sorted address mapping, (address, traffic at current timestamp, UTC timestamp(seconds))
    pool: RwLock<Vec<(Ipv4Addr, AtomicCell<(u64, i64)>)>>
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum PushResult {
    Accept,
    Reject
}

impl FlowControl {
    pub fn new(mut rule: Vec<(Ipv4Net, u64)>) -> Self {
        rule.sort_unstable_by_key(|(cidr, _)| std::cmp::Reverse(cidr.prefix_len()));

        FlowControl {
            rule,
            pool: RwLock::new(Vec::new())
        }
    }

    pub fn push(
        &self,
        packet_dst: Ipv4Addr,
        packet_len: u64
    ) -> PushResult {
        let limit_opt = self.rule.iter()
            .find(|(cidr, _)| cidr.contains(&packet_dst))
            .map(|(_, limit)| *limit);

        let limit = match limit_opt {
            None => return PushResult::Accept,
            Some(limit) => limit
        };

        if packet_len > limit {
            return PushResult::Reject;
        }

        let guard = self.pool.read();
        let now = Utc::now().timestamp();

        let index_opt = guard.binary_search_by_key(&packet_dst, |(addr, _)| *addr);

        let index = match index_opt {
            Ok(v) => v,
            Err(_) => return PushResult::Reject,
        };

        let (_, value) = &(*guard)[index];

        let res = value.fetch_update(|(f, t)| {
            if t == now {
                let new_traffic = f + packet_len;

                if new_traffic <= limit {
                    Some((new_traffic, t))
                } else {
                    None
                }
            } else {
                Some((packet_len, now))
            }
        });

        if res.is_ok() {
            PushResult::Accept
        } else {
            PushResult::Reject
        }
    }

    pub fn add_address(&self, addr: Ipv4Addr) {
        let mut guard = self.pool.write();
        let index_opt = guard.binary_search_by_key(&addr, |(addr, _)| *addr);

        if let Err(i) = index_opt {
            let v = (addr, AtomicCell::new((0, Utc::now().timestamp())));
            guard.insert(i, v);
        }
    }

    pub fn remove_address(&self, addr: &Ipv4Addr) {
        let mut guard = self.pool.write();
        let index_opt = guard.binary_search_by_key(addr, |(addr, _)| *addr);

        if let Ok(i) = index_opt {
            guard.remove(i);
        }
    }
}

pub mod protocol {
    use std::error::Error;
    use std::fmt::{Display, Formatter};
    use std::io;
    use std::mem::size_of;
    use std::net::{Ipv4Addr, SocketAddr};

    use ahash::HashMap;
    use anyhow::{anyhow, Result};
    use arrayvec::ArrayVec;
    use bincode::{config, Decode, Encode};
    use ipnet::Ipv4Net;
    use serde::{Deserialize, Serialize};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

    use crate::common::cipher;
    use crate::common::cipher::Cipher;

    pub type VirtualAddr = Ipv4Addr;

    pub const SERVER_VIRTUAL_ADDR: VirtualAddr = VirtualAddr::new(9, 9, 9, 9);

    pub const TCP_BUFF_SIZE: usize = 65535;
    pub const UDP_BUFF_SIZE: usize = 65535;

    pub const MAGIC_NUM: u8 = 0x99;
    pub const REGISTER: u8 = 0x00;
    pub const REGISTER_RESULT: u8 = 0x05;
    pub const NODE_MAP: u8 = 0x01;
    pub const HEARTBEAT: u8 = 0x02;
    pub const DATA: u8 = 0x03;
    pub const GET_IDLE_VIRTUAL_ADDR: u8 = 0x06;
    pub const GET_IDLE_VIRTUAL_ADDR_RES: u8 = 0x07;
    pub const RELAY: u8 = 0x08;
    pub const REQ: u8 = 0x00;
    pub const RESP: u8 = 0x01;

    pub type Seq = u32;
    pub type NetProtocols = ArrayVec<NetProtocol, 2>;

    #[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
    pub enum NetProtocol {
        TCP,
        UDP,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct ProtocolMode {
        pub p2p: NetProtocols,
        pub relay: NetProtocols,
    }

    impl Default for ProtocolMode {
        fn default() -> Self {
            let mut p2p = NetProtocols::new();
            p2p.push(NetProtocol::UDP);

            ProtocolMode {
                p2p,
                relay: NetProtocols::from([NetProtocol::UDP, NetProtocol::TCP]),
            }
        }
    }

    impl ProtocolMode {
        pub fn is_use_udp(&self) -> bool {
            self.p2p.contains(&NetProtocol::UDP) || self.relay.contains(&NetProtocol::UDP)
        }

        pub fn is_use_tcp(&self) -> bool {
            self.p2p.contains(&NetProtocol::TCP) || self.relay.contains(&NetProtocol::TCP)
        }
    }

    #[derive(Encode, Decode, Clone)]
    pub struct GroupContent {
        pub name: String,
        #[bincode(with_serde)]
        pub cidr: Ipv4Net,
    }

    #[derive(Encode, Decode, Clone)]
    pub struct Register {
        pub node_name: String,
        pub virtual_addr: VirtualAddr,
        pub lan_udp_socket_addr: Option<SocketAddr>,
        #[bincode(with_serde)]
        pub proto_mod: ProtocolMode,
        #[bincode(with_serde)]
        pub allowed_ips: Vec<Ipv4Net>,
        pub register_time: i64,
        pub nonce: u32,
    }

    #[derive(Eq, PartialEq, Debug, Copy, Clone, Encode, Decode)]
    pub enum AllocateError {
        IpNotBelongNetworkRange,
        IpSameAsNetworkAddress,
        IpSameAsBroadcastAddress,
        IpAlreadyInUse,
    }

    impl Display for AllocateError {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self)
        }
    }

    impl Error for AllocateError {}

    #[derive(Clone, Copy, Debug, Encode, Decode)]
    pub enum RegisterError {
        InvalidVirtualAddress(AllocateError),
        Timeout,
        NonceRepeat,
    }

    impl Display for RegisterError {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self)
        }
    }

    impl Error for RegisterError {}

    #[derive(Encode, Decode, Deserialize, Serialize, Clone)]
    pub struct Node {
        pub name: String,
        pub virtual_addr: VirtualAddr,
        pub lan_udp_addr: Option<SocketAddr>,
        pub wan_udp_addr: Option<SocketAddr>,
        #[bincode(with_serde)]
        pub mode: ProtocolMode,
        #[bincode(with_serde)]
        pub allowed_ips: Vec<Ipv4Net>,
        pub register_time: i64,
        pub register_nonce: u32,
    }

    #[repr(u8)]
    pub enum HeartbeatType {
        Req = 0,
        Resp,
    }

    impl TryFrom<u8> for HeartbeatType {
        type Error = anyhow::Error;

        fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
            match value {
                REQ => Ok(HeartbeatType::Req),
                RESP => Ok(HeartbeatType::Resp),
                _ => Err(anyhow!("Heartbeat type not match")),
            }
        }
    }

    pub enum TcpMsg<'a> {
        GetIdleVirtualAddr,
        // ip address, cidr
        GetIdleVirtualAddrRes(Option<(VirtualAddr, Ipv4Net)>),
        // todo add signature
        Register(Register),
        RegisterRes(Result<GroupContent, RegisterError>),
        NodeMap(HashMap<VirtualAddr, Node>),
        // todo convert to data
        Relay(VirtualAddr, &'a [u8]),
        Heartbeat(Seq, HeartbeatType),
    }

    pub const TCP_MSG_HEADER_LEN: usize = 4;

    // |MAGIC NUM|PACKET TYPE|DATA LEN|DATA|
    impl TcpMsg<'_> {
        pub fn get_idle_virtual_addr_encode(out: &mut [u8]) -> usize {
            out[0] = MAGIC_NUM;
            out[1] = GET_IDLE_VIRTUAL_ADDR;
            out[2..4].copy_from_slice(&0u16.to_be_bytes());
            TCP_MSG_HEADER_LEN
        }

        pub fn get_idle_virtual_addr_res_encode(
            addr: Option<(VirtualAddr, Ipv4Net)>,
            out: &mut [u8],
        ) -> Result<usize> {
            out[0] = MAGIC_NUM;
            out[1] = GET_IDLE_VIRTUAL_ADDR_RES;

            let size = bincode::encode_into_slice(
                bincode::serde::Compat(addr),
                &mut out[TCP_MSG_HEADER_LEN..],
                config::standard(),
            )?;

            out[2..4].copy_from_slice(&(size as u16).to_be_bytes());
            Ok(TCP_MSG_HEADER_LEN + size)
        }

        pub fn node_map_encode(
            node_map: &HashMap<VirtualAddr, Node>,
            out: &mut [u8],
        ) -> Result<usize> {
            out[0] = MAGIC_NUM;
            out[1] = NODE_MAP;

            let size = bincode::encode_into_slice(
                node_map,
                &mut out[TCP_MSG_HEADER_LEN..],
                config::standard(),
            )?;
            out[2..4].copy_from_slice(&(size as u16).to_be_bytes());

            Ok(TCP_MSG_HEADER_LEN + size)
        }

        pub fn register_encode(register: &Register, out: &mut [u8]) -> Result<usize> {
            out[0] = MAGIC_NUM;
            out[1] = REGISTER;

            let size = bincode::encode_into_slice(
                register,
                &mut out[TCP_MSG_HEADER_LEN..],
                config::standard(),
            )?;
            out[2..4].copy_from_slice(&(size as u16).to_be_bytes());

            Ok(TCP_MSG_HEADER_LEN + size)
        }

        pub fn register_res_encode(
            register_res: &Result<GroupContent, RegisterError>,
            out: &mut [u8],
        ) -> Result<usize> {
            out[0] = MAGIC_NUM;
            out[1] = REGISTER_RESULT;

            let size = bincode::encode_into_slice(
                register_res,
                &mut out[TCP_MSG_HEADER_LEN..],
                config::standard(),
            )?;
            out[2..4].copy_from_slice(&(size as u16).to_be_bytes());

            Ok(TCP_MSG_HEADER_LEN + size)
        }

        pub fn relay_encode(to: VirtualAddr, packet_size: usize, out: &mut [u8]) -> usize {
            out[0] = MAGIC_NUM;
            out[1] = RELAY;

            let data_size = size_of::<VirtualAddr>() + packet_size;
            out[2..4].copy_from_slice(&(data_size as u16).to_be_bytes());
            out[TCP_MSG_HEADER_LEN..TCP_MSG_HEADER_LEN + size_of::<VirtualAddr>()]
                .copy_from_slice(&to.octets());

            TCP_MSG_HEADER_LEN + data_size
        }

        pub fn heartbeat_encode(seq: Seq, heartbeat_type: HeartbeatType, out: &mut [u8]) -> usize {
            out[0] = MAGIC_NUM;
            out[1] = HEARTBEAT;

            const DATA_SIZE: usize = size_of::<Seq>() + size_of::<HeartbeatType>();

            out[2..4].copy_from_slice(&(DATA_SIZE as u16).to_be_bytes());
            out[TCP_MSG_HEADER_LEN..TCP_MSG_HEADER_LEN + size_of::<Seq>()]
                .copy_from_slice(&seq.to_be_bytes());
            out[TCP_MSG_HEADER_LEN + size_of::<Seq>()] = heartbeat_type as u8;

            TCP_MSG_HEADER_LEN + DATA_SIZE
        }

        fn decode(mode: u8, data: &[u8]) -> Result<TcpMsg> {
            let msg = match mode {
                REGISTER => {
                    let (register, _) =
                        bincode::decode_from_slice::<Register, _>(data, config::standard())?;
                    TcpMsg::Register(register)
                }
                REGISTER_RESULT => {
                    let (res, _) = bincode::decode_from_slice::<
                        Result<GroupContent, RegisterError>,
                        _,
                    >(data, config::standard())?;
                    TcpMsg::RegisterRes(res)
                }
                NODE_MAP => {
                    let (node_map, _) = bincode::decode_from_slice::<HashMap<VirtualAddr, Node>, _>(
                        data,
                        config::standard(),
                    )?;
                    TcpMsg::NodeMap(node_map)
                }
                RELAY => {
                    const ADDR_SIZE: usize = size_of::<VirtualAddr>();

                    let mut virtual_addr_buff = [0u8; ADDR_SIZE];
                    virtual_addr_buff.copy_from_slice(get!(data, ..ADDR_SIZE));
                    let virtual_addr = VirtualAddr::from(virtual_addr_buff);

                    TcpMsg::Relay(virtual_addr, &data[ADDR_SIZE..])
                }
                HEARTBEAT => {
                    const SEQ_SIZE: usize = size_of::<Seq>();

                    let mut seq = [0u8; SEQ_SIZE];
                    seq.copy_from_slice(get!(data, ..SEQ_SIZE));
                    let seq = Seq::from_be_bytes(seq);

                    let heartbeat_type = *get!(data, SEQ_SIZE);
                    let heartbeat_type = HeartbeatType::try_from(heartbeat_type)?;
                    TcpMsg::Heartbeat(seq, heartbeat_type)
                }
                GET_IDLE_VIRTUAL_ADDR => TcpMsg::GetIdleVirtualAddr,
                GET_IDLE_VIRTUAL_ADDR_RES => {
                    let (opt, _) = bincode::decode_from_slice::<
                        bincode::serde::Compat<Option<(VirtualAddr, Ipv4Net)>>,
                        _,
                    >(data, config::standard())?;
                    TcpMsg::GetIdleVirtualAddrRes(opt.0)
                }
                _ => return Err(anyhow!("invalid tcp msg")),
            };
            Ok(msg)
        }

        pub async fn read_msg<'a, Rx: AsyncRead + Unpin, K: Cipher>(
            rx: &mut Rx,
            key: &K,
            buff: &'a mut [u8],
        ) -> Result<Option<TcpMsg<'a>>> {
            if rx.read_exact(&mut buff[..4]).await.is_err() {
                return Ok(None);
            }

            let mut ctx = cipher::CipherContext {
                offset: 0,
                expect_prefix: Some(&[MAGIC_NUM]),
                key_timestamp: None,
            };
            key.decrypt(&mut buff[..4], &mut ctx);

            if buff[0] != MAGIC_NUM {
                return Err(anyhow!("magic number miss match"));
            }

            let mode = buff[1];
            let mut len_buff = [0u8; 2];
            len_buff.copy_from_slice(&buff[2..4]);
            let len = u16::from_be_bytes(len_buff);

            let buff = &mut buff[..len as usize];
            rx.read_exact(buff).await?;

            ctx.offset = 4;
            ctx.expect_prefix = None;
            key.decrypt(buff, &mut ctx);
            TcpMsg::decode(mode, buff).map(Some)
        }

        pub async fn write_msg<Tx: AsyncWrite + Unpin, K: Cipher>(
            tx: &mut Tx,
            key: &K,
            input: &mut [u8],
        ) -> Result<()> {
            key.encrypt(input, &mut cipher::CipherContext::default());
            tx.write_all(input).await?;
            Ok(())
        }
    }

    pub enum UdpMsg<'a> {
        // todo Heartbeat(from, to, seq, type)
        Heartbeat(VirtualAddr, Seq, HeartbeatType),
        #[allow(unused)]
        Data(&'a [u8]),
        // todo remove relay
        Relay(VirtualAddr, &'a [u8]),
    }

    pub const UDP_MSG_HEADER_LEN: usize = 2;

    impl UdpMsg<'_> {
        pub fn heartbeat_encode(
            addr: VirtualAddr,
            seq: Seq,
            heartbeat_type: HeartbeatType,
            out: &mut [u8],
        ) -> usize {
            out[0] = MAGIC_NUM;
            out[1] = HEARTBEAT;
            out[2..6].copy_from_slice(&addr.octets());
            out[6..10].copy_from_slice(&seq.to_be_bytes());

            out[10] = heartbeat_type as u8;
            UDP_MSG_HEADER_LEN
                + size_of::<VirtualAddr>()
                + size_of::<Seq>()
                + size_of::<HeartbeatType>()
        }

        pub fn data_encode(packet_len: usize, out: &mut [u8]) -> usize {
            out[0] = MAGIC_NUM;
            out[1] = DATA;
            UDP_MSG_HEADER_LEN + packet_len
        }

        pub fn relay_encode(to: VirtualAddr, packet_len: usize, out: &mut [u8]) -> usize {
            out[0] = MAGIC_NUM;
            out[1] = RELAY;
            out[2..6].copy_from_slice(&to.octets());
            UDP_MSG_HEADER_LEN + size_of::<VirtualAddr>() + packet_len
        }

        pub fn decode(packet: &[u8]) -> Result<UdpMsg> {
            let magic_num = packet[0];
            let mode = packet[1];
            let data = &packet[2..];

            if magic_num != MAGIC_NUM {
                return Err(anyhow!("magic number miss match"));
            };

            match mode {
                DATA => Ok(UdpMsg::Data(data)),
                RELAY => {
                    let mut virtual_addr = [0u8; 4];
                    virtual_addr.copy_from_slice(get!(data, ..4));
                    let virtual_addr = VirtualAddr::from(virtual_addr);

                    Ok(UdpMsg::Relay(virtual_addr, &data[4..]))
                }
                HEARTBEAT => {
                    let mut virtual_addr = [0u8; 4];
                    virtual_addr.copy_from_slice(get!(data, ..4));
                    let virtual_addr = VirtualAddr::from(virtual_addr);

                    let mut seq = [0u8; 4];
                    seq.copy_from_slice(get!(data, 4..8));
                    let seq: Seq = u32::from_be_bytes(seq);

                    let heartbeat_type = *get!(data, 8);

                    let heartbeat_type = match heartbeat_type {
                        REQ => HeartbeatType::Req,
                        RESP => HeartbeatType::Resp,
                        _ => return Err(anyhow!("invalid udp message")),
                    };
                    Ok(UdpMsg::Heartbeat(virtual_addr, seq, heartbeat_type))
                }
                _ => Err(anyhow!("invalid udp message")),
            }
        }
    }
}
