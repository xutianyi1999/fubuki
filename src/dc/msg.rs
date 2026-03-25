//! Inner payloads (after FBDC decrypt).

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

pub const HELLO: u16 = 1;
pub const MEMBER_ANNOUNCE: u16 = 4;
/// Reflexive endpoints for hole punching + neighbor fan-out (PSK encrypted).
pub const NEIGHBOR_SYNC: u16 = 8;
pub const DATA_IP: u16 = 16;

/// Decrypted control-plane envelope: optional unicast target plus bincode payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inner {
    /// Target peer `node_id` for unicast; `None` means every neighbor should process the message.
    pub dst: Option<[u8; 16]>,
    /// Message-specific body (`HelloBody`, `DirectoryEntryWire`, etc.) encoded with bincode.
    pub payload: Vec<u8>,
}

/// Payload of a [`HELLO`] message: identity and listen endpoint for a new or refreshed peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloBody {
    /// UDP port this peer binds for FBDC (underlay).
    pub listen_port: u16,
    /// Human-readable label (may be truncated when sent).
    pub display_name: String,
    /// Overlay IPv4 address and prefix assigned to this peer.
    pub virtual_net: Ipv4Net,
    /// Monotonic directory row version; bumps when peer-visible fields change (see `row_version`).
    pub row_version: u64,
}

/// One row of the replicated member directory as carried in [`MEMBER_ANNOUNCE`] (and derived from [`HelloBody`]).
///
/// `direct_ip` / `direct_port` are optional underlay hints; if absent, receivers infer `direct_udp` from the packet source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryEntryWire {
    /// Stable 128-bit member id (UUID bytes).
    pub node_id: [u8; 16],
    pub display_name: String,
    /// Overlay address for this member.
    pub virtual_net: Ipv4Net,
    /// Row version for merge ordering (same semantics as [`HelloBody::row_version`]).
    pub version: u64,
    /// Optional IPv4 for UDP reachability when it differs from the observed source (big-endian octets).
    pub direct_ip: Option<[u8; 4]>,
    /// UDP port paired with [`Self::direct_ip`]; both must be set to use the hint.
    pub direct_port: Option<u16>,
}

/// Single reachability tuple inside [`NEIGHBOR_SYNC`]: maps a member to an underlay UDP endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReachEntry {
    /// Member this row refers to.
    pub node_id: [u8; 16],
    /// Overlay host address octets (with [`Self::virtual_prefix_len`]) so lookups work before HELLO arrives.
    pub virtual_ip: [u8; 4],
    /// CIDR prefix length for [`Self::virtual_ip`].
    pub virtual_prefix_len: u8,
    /// IPv4 address to send FBDC datagrams to (underlay).
    pub ip: [u8; 4],
    /// UDP port on [`Self::ip`].
    pub port: u16,
}

/// Full payload of [`NEIGHBOR_SYNC`]: bounded set of [`ReachEntry`] built from the local directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeighborSyncBody {
    /// Gossiped reachability rows (capped when building, see `MAX_SYNC_ENTRIES`).
    pub entries: Vec<ReachEntry>,
}

impl DirectoryEntryWire {
    pub fn from_self(
        node_id: [u8; 16],
        display_name: String,
        virtual_net: Ipv4Net,
        row_version: u64,
    ) -> Self {
        DirectoryEntryWire {
            node_id,
            display_name,
            virtual_net,
            version: row_version,
            direct_ip: None,
            direct_port: None,
        }
    }

    pub fn from_hello(node_id: [u8; 16], h: HelloBody) -> Self {
        DirectoryEntryWire {
            node_id,
            display_name: h.display_name,
            virtual_net: h.virtual_net,
            version: h.row_version,
            direct_ip: None,
            direct_port: None,
        }
    }
}

pub fn encode_inner(inner: &Inner) -> anyhow::Result<Vec<u8>> {
    Ok(bincode::serde::encode_to_vec(
        inner,
        bincode::config::standard(),
    )?)
}

pub fn decode_inner(bytes: &[u8]) -> anyhow::Result<Inner> {
    let (v, _) = bincode::serde::decode_from_slice(bytes, bincode::config::standard())?;
    Ok(v)
}

pub fn encode_hello(h: &HelloBody) -> anyhow::Result<Vec<u8>> {
    Ok(bincode::serde::encode_to_vec(
        h,
        bincode::config::standard(),
    )?)
}

pub fn decode_hello(bytes: &[u8]) -> anyhow::Result<HelloBody> {
    let (v, _) = bincode::serde::decode_from_slice(bytes, bincode::config::standard())?;
    Ok(v)
}

pub fn encode_directory_entry(e: &DirectoryEntryWire) -> anyhow::Result<Vec<u8>> {
    Ok(bincode::serde::encode_to_vec(
        e,
        bincode::config::standard(),
    )?)
}

pub fn decode_directory_entry(bytes: &[u8]) -> anyhow::Result<DirectoryEntryWire> {
    let (v, _) = bincode::serde::decode_from_slice(bytes, bincode::config::standard())?;
    Ok(v)
}

pub fn encode_neighbor_sync(b: &NeighborSyncBody) -> anyhow::Result<Vec<u8>> {
    Ok(bincode::serde::encode_to_vec(
        b,
        bincode::config::standard(),
    )?)
}

pub fn decode_neighbor_sync(bytes: &[u8]) -> anyhow::Result<NeighborSyncBody> {
    let (v, _) = bincode::serde::decode_from_slice(bytes, bincode::config::standard())?;
    Ok(v)
}
