use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use ahash::HashMap;
use parking_lot::Mutex;
use tokio::net::UdpSocket;
use tokio::signal;
use tokio::time::{interval, MissedTickBehavior};

use crate::platform::sys_route::{Route, SystemRouteHandle};
use crate::platform::tun::TunDevice;

use super::config::DcConfig;
use super::crypto::{build_aad, decrypt, encrypt, DcKeys};
use super::directory::Directory;
use super::frame;
use super::msg::{
    decode_directory_entry, decode_inner, decode_neighbor_sync,
    encode_directory_entry, encode_inner, encode_neighbor_sync,
    DirectoryEntryWire, Inner, DATA_IP, MEMBER_ANNOUNCE, NEIGHBOR_SYNC,
};
use super::row_version;
use super::stun;

const TUN_MTU: usize = 1420;
/// Plaintext hole-punch probe: magic + sender `node_id`.
const PUNCH_HDR: &[u8] = b"PCH\x01";
const PUNCH_BYTES: usize = PUNCH_HDR.len() + 16;
const PUNCH_BURST: usize = 8;

/// Per-process STUN client state (binding requests on the mesh UDP socket).
struct StunTrack {
    /// Pending transaction: start time and 12-byte STUN transaction id.
    inflight: Option<(Instant, [u8; 12])>,
    /// When a binding response was last accepted.
    last_ok: Option<Instant>,
    /// Round-robin index into [`DcConfig::stun_servers`].
    next_server_idx: usize,
}

fn load_or_create_node_id(path: &std::path::Path) -> Result<[u8; 16]> {
    if path.exists() {
        let s = std::fs::read_to_string(path).with_context(|| path.display().to_string())?;
        let line = s.lines().next().unwrap_or("").trim();
        let u = uuid::Uuid::parse_str(line).map_err(|e| anyhow!("node id file: {e}"))?;
        return Ok(*u.as_bytes());
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).ok();
    }
    let u = uuid::Uuid::new_v4();
    std::fs::write(path, format!("{u}\n")).with_context(|| path.display().to_string())?;
    Ok(*u.as_bytes())
}

/// Shared daemon state for UDP receive loop, gossip ticks, and crypto.
struct DcShared {
    /// Loaded `dc.json` (overlay net, bootstrap, STUN, etc.).
    cfg: DcConfig,
    /// Derived PSK keys for control vs data frames.
    keys: DcKeys,
    /// This instance's stable member id.
    node_id: [u8; 16],
    /// Effective display name after trimming / hostname fallback.
    display_name: String,
    /// Current directory row version for MEMBER_ANNOUNCE.
    row_version: u64,
    /// Monotonic outer nonce for outbound AEAD (see also per-sender replay map).
    send_nonce: AtomicU64,
    /// Last accepted outer nonce per peer `node_id` (replay protection for decrypt).
    last_rx: Mutex<HashMap<[u8; 16], u64>>,
    /// Member table and gossip neighbor LRU.
    directory: Directory,
    /// STUN query bookkeeping.
    stun: Mutex<StunTrack>,
}

impl DcShared {
    fn next_nonce(&self) -> u64 {
        self.send_nonce.fetch_add(1, Ordering::Relaxed)
    }

    fn accept_nonce(&self, sender: [u8; 16], n: u64) -> bool {
        let mut m = self.last_rx.lock();
        match m.get(&sender) {
            Some(p) if n <= *p => false,
            _ => {
                m.insert(sender, n);
                true
            }
        }
    }

    fn pack(&self, msg_type: u16, data_key: bool, inner: Inner) -> Result<Vec<u8>> {
        let plain = encode_inner(&inner)?;
        let nonce = self.next_nonce();
        let aad = build_aad(
            &frame::MAGIC,
            frame::PROTO_VERSION,
            msg_type,
            &self.node_id,
            nonce,
        );
        let key = if data_key {
            &self.keys.k_data
        } else {
            &self.keys.k_control
        };
        let ct = encrypt(key, &aad, nonce, msg_type, &plain)?;
        Ok(frame::encode(msg_type, &self.node_id, nonce, &ct))
    }

    fn unpack(
        &self,
        msg_type: u16,
        sender: [u8; 16],
        nonce: u64,
        ciphertext: &[u8],
    ) -> Result<Inner> {
        let data_key = msg_type == DATA_IP;
        let key = if data_key {
            &self.keys.k_data
        } else {
            &self.keys.k_control
        };
        let aad = build_aad(
            &frame::MAGIC,
            frame::PROTO_VERSION,
            msg_type,
            &sender,
            nonce,
        );
        let plain = decrypt(key, &aad, nonce, msg_type, ciphertext)?;
        if !self.accept_nonce(sender, nonce) {
            return Err(anyhow!("dc: nonce replay"));
        }
        decode_inner(&plain)
    }
}

fn inner_for_me(inner: &Inner, self_id: &[u8; 16]) -> bool {
    match &inner.dst {
        None => true,
        Some(d) => d == self_id,
    }
}

fn try_consume_stun_response(s: &DcShared, buf: &[u8], now: Instant) -> bool {
    let mut st = s.stun.lock();
    let tid = match &st.inflight {
        Some((_, t)) => *t,
        None => return false,
    };
    let Some((ip, port)) = stun::try_parse_binding_response(buf, &tid) else {
        return false;
    };
    st.inflight = None;
    st.last_ok = Some(now);
    drop(st);
    let sa = SocketAddrV4::new(ip, port);
    s.directory.set_self_reflexive(s.node_id, sa, now);
    debug!("dc: STUN reflexive {ip}:{port}");
    true
}

fn try_consume_punch(s: &DcShared, buf: &[u8], from: SocketAddr, now: Instant) -> bool {
    if buf.len() < PUNCH_BYTES || &buf[..PUNCH_HDR.len()] != PUNCH_HDR {
        return false;
    }
    let mut peer = [0u8; 16];
    peer.copy_from_slice(&buf[PUNCH_HDR.len()..PUNCH_BYTES]);
    if let SocketAddr::V4(v4) = from {
        s.directory.note_punch_from(peer, v4, now);
    }
    true
}

async fn tick_stun(s: &DcShared, sock: &UdpSocket) -> Result<()> {
    if s.cfg.stun_servers.is_empty() {
        return Ok(());
    }
    let now = Instant::now();
    let self_rx = s.directory.self_reflexive(s.node_id);
    let (server_str, tid) = {
        let mut st = s.stun.lock();
        if let Some((started, _)) = st.inflight {
            if now.duration_since(started) > Duration::from_secs(5) {
                st.inflight = None;
            } else {
                return Ok(());
            }
        }
        let need_query = self_rx.is_none()
            || st
                .last_ok
                .map(|t| now.duration_since(t) >= Duration::from_secs(45))
                .unwrap_or(true);
        if !need_query {
            return Ok(());
        }
        let idx = st.next_server_idx % s.cfg.stun_servers.len();
        st.next_server_idx = st.next_server_idx.wrapping_add(1);
        let full = *uuid::Uuid::new_v4().as_bytes();
        let mut t = [0u8; 12];
        t.copy_from_slice(&full[..12]);
        st.inflight = Some((now, t));
        (s.cfg.stun_servers[idx].clone(), t)
    };
    let Some(stun_sa) = stun::resolve_stun_server(&server_str).await else {
        s.stun.lock().inflight = None;
        return Ok(());
    };
    let req = stun::binding_request(tid).context("dc: stun binding encode")?;
    if sock.send_to(&req, stun_sa).await.is_err() {
        s.stun.lock().inflight = None;
    }
    Ok(())
}

async fn punch_burst(sock: &UdpSocket, to: SocketAddrV4, my_id: &[u8; 16]) {
    let mut pkt = [0u8; PUNCH_BYTES];
    pkt[..PUNCH_HDR.len()].copy_from_slice(PUNCH_HDR);
    pkt[PUNCH_HDR.len()..].copy_from_slice(my_id);
    for _ in 0..PUNCH_BURST {
        let _ = sock.send_to(&pkt, SocketAddr::V4(to)).await;
    }
}

fn self_directory_row(s: &DcShared) -> DirectoryEntryWire {
    DirectoryEntryWire::from_self(
        s.node_id,
        s.display_name.clone(),
        s.cfg.virtual_net,
        s.row_version,
    )
}

/// Serialized [`MEMBER_ANNOUNCE`] frame (shared by bootstrap send and periodic gossip).
fn pack_member_announce(s: &DcShared) -> Result<Vec<u8>> {
    let wire = self_directory_row(s);
    let inner = Inner {
        dst: None,
        payload: encode_directory_entry(&wire)?,
    };
    s.pack(MEMBER_ANNOUNCE, false, inner)
}

pub async fn run(config_path: &Path) -> Result<()> {
    let cfg = DcConfig::load(config_path)?;
    let row_version = row_version::load_or_bump(&cfg)?;
    let net_id = cfg.network_id_bytes()?;
    let keys = DcKeys::derive(cfg.psk.as_bytes(), &net_id)?;
    let id_path = cfg
        .node_id_path
        .clone()
        .unwrap_or_else(|| cfg.default_node_id_path());
    let node_id = load_or_create_node_id(&id_path)?;
    info!(
        "dc: network {} node {}",
        cfg.network_id,
        uuid::Uuid::from_bytes(node_id)
    );

    let mut display = if cfg.display_name.trim().is_empty() {
        gethostname::gethostname()
            .to_string_lossy()
            .into_owned()
    } else {
        cfg.display_name.clone()
    };
    if display.len() > 64 {
        display.truncate(64);
    }

    // Resolve bootstrap before TUN/routes so a DNS failure does not leave system routes behind.
    let bootstrap = cfg.bootstrap_addrs().await?;

    let vnet = cfg.virtual_net;
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, cfg.listen_udp))
        .await
        .with_context(|| format!("dc: bind UDP {}", cfg.listen_udp))?;
    let socket = Arc::new(socket);

    let tun = crate::platform::tun::create().context("dc: TUN create")?;
    let netmask = vnet.netmask();
    tun
        .add_addr(vnet.addr(), netmask)
        .context("dc: tun add_addr")?;
    tun.set_mtu(TUN_MTU).context("dc: tun mtu")?;
    let tun_index = tun.get_index();

    let mut sys = SystemRouteHandle::new().context("dc: system routes")?;
    let network = vnet.network();
    #[allow(unused_mut)]
    let mut route = Route::new(IpAddr::V4(network), vnet.prefix_len())
        .with_gateway(IpAddr::V4(vnet.addr()))
        .with_ifindex(tun_index);
    #[cfg(any(target_os = "windows", target_os = "linux"))]
    {
        route = route.with_metric(1);
    }
    sys.add(std::slice::from_ref(&route)).await?;

    let directory = Directory::new();
    directory.upsert_self(
        node_id,
        display.clone(),
        vnet,
        row_version,
        Instant::now(),
    );

    directory.seed_neighbors(&bootstrap);

    let shared = Arc::new(DcShared {
        cfg,
        keys,
        node_id,
        display_name: display,
        row_version,
        send_nonce: AtomicU64::new(1),
        last_rx: Mutex::new(HashMap::default()),
        directory,
        stun: Mutex::new(StunTrack {
            inflight: None,
            last_ok: None,
            next_server_idx: 0,
        }),
    });

    for a in &bootstrap {
        let _ = send_member_announce_to(&shared, socket.as_ref(), *a).await;
    }

    let mut udp_buf = vec![0u8; 65536];
    let mut tun_buf = vec![0u8; 65536];
    let mut tick = interval(std::time::Duration::from_secs(3));
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            r = socket.recv_from(&mut udp_buf) => {
                let (n, from) = r.context("dc: udp recv")?;
                if let Err(e) = handle_udp_datagram(
                    &shared,
                    socket.as_ref(),
                    &tun,
                    &udp_buf[..n],
                    from,
                ).await {
                    debug!("dc: udp handle: {e:?}");
                }
            }
            r = tun.recv_packet(&mut tun_buf) => {
                let n = r.context("dc: tun recv")?;
                if n == 0 { continue; }
                if let Err(e) = handle_tun_out(&shared, socket.as_ref(), &tun_buf[..n]).await {
                    debug!("dc: tun out: {e:?}");
                }
            }
            _ = tick.tick() => {
                if let Err(e) = gossip(&shared, socket.as_ref()).await {
                    warn!("dc: gossip: {e:?}");
                }
            }
            _ = signal::ctrl_c() => {
                info!("dc: exiting");
                break;
            }
        }
    }

    let _ = sys.clear().await;
    Ok(())
}

async fn send_member_announce_to(s: &DcShared, sock: &UdpSocket, to: SocketAddr) -> Result<()> {
    let pkt = pack_member_announce(s)?;
    sock.send_to(&pkt, to).await?;
    Ok(())
}

async fn gossip(s: &DcShared, sock: &UdpSocket) -> Result<()> {
    tick_stun(s, sock).await?;

    let announce = pack_member_announce(s)?;
    let sync_body = s.directory.build_neighbor_sync(s.node_id);
    let sync_pkt = if !sync_body.entries.is_empty() {
        Some(s.pack(
            NEIGHBOR_SYNC,
            false,
            Inner {
                dst: None,
                payload: encode_neighbor_sync(&sync_body)?,
            },
        )?)
    } else {
        None
    };

    let neighbors = s.directory.neighbors_snapshot();
    for a in &neighbors {
        let _ = sock.send_to(&announce, *a).await;
        if let Some(ref p) = sync_pkt {
            let _ = sock.send_to(p, *a).await;
        }
    }

    for t in s.directory.punch_targets(s.node_id) {
        punch_burst(sock, t, &s.node_id).await;
    }

    Ok(())
}

async fn handle_udp_datagram<T: TunDevice>(
    s: &DcShared,
    sock: &UdpSocket,
    tun: &T,
    buf: &[u8],
    from: SocketAddr,
) -> Result<()> {
    let _ = sock;
    let now = Instant::now();
    s.directory.add_neighbor(from);
    if try_consume_stun_response(s, buf, now) {
        return Ok(());
    }
    if try_consume_punch(s, buf, from, now) {
        return Ok(());
    }
    let Some(f) = frame::decode(buf) else {
        return Ok(());
    };
    if f.sender == s.node_id {
        return Ok(());
    }

    if f.msg_type == DATA_IP {
        match s.unpack(f.msg_type, f.sender, f.nonce, f.ciphertext) {
            Ok(inner) => {
                if inner_for_me(&inner, &s.node_id) && !inner.payload.is_empty() {
                    tun.send_packet(&inner.payload).await?;
                }
            }
            Err(_) => {}
        }
        return Ok(());
    }

    let inner = match s.unpack(f.msg_type, f.sender, f.nonce, f.ciphertext) {
        Ok(i) => i,
        Err(_) => return Ok(()),
    };
    if !inner_for_me(&inner, &s.node_id) {
        return Ok(());
    }

    match f.msg_type {
        MEMBER_ANNOUNCE => {
            let w = decode_directory_entry(&inner.payload)?;
            if w.node_id != f.sender {
                debug!("dc: MEMBER row node_id != frame sender; ignored");
            } else {
                s.directory.merge_wire(w, from, now);
            }
        }
        NEIGHBOR_SYNC => {
            let body = decode_neighbor_sync(&inner.payload)?;
            s.directory.merge_neighbor_sync(&body, now);
        }
        _ => {}
    }
    Ok(())
}

async fn handle_tun_out(s: &DcShared, sock: &UdpSocket, packet: &[u8]) -> Result<()> {
    let dst = match crate::common::net::get_ip_dst_addr(packet) {
        Ok(d) => d,
        Err(_) => return Ok(()),
    };
    if !s.cfg.virtual_net.contains(&dst) {
        return Ok(());
    }
    if dst == s.cfg.virtual_net.addr() {
        return Ok(());
    }
    let Some(target) = s.directory.lookup_udp_for_dst(dst, s.node_id) else {
        return Ok(());
    };
    let inner = Inner {
        dst: None,
        payload: packet.to_vec(),
    };
    let pkt = s.pack(DATA_IP, true, inner)?;
    sock.send_to(&pkt, SocketAddr::V4(target)).await?;
    Ok(())
}
