//! Inner payloads (after FBDC decrypt).

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

pub const HELLO: u16 = 1;
pub const MEMBER_ANNOUNCE: u16 = 4;
/// Reflexive endpoints for hole punching + neighbor fan-out (PSK encrypted).
pub const NEIGHBOR_SYNC: u16 = 8;
pub const DATA_IP: u16 = 16;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inner {
    /// `None` = broadcast to neighbors
    pub dst: Option<[u8; 16]>,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloBody {
    pub listen_port: u16,
    pub display_name: String,
    pub virtual_net: Ipv4Net,
    pub row_version: u64,
}

/// Optional UDP reachability hint (often filled from packet source by receiver).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryEntryWire {
    pub node_id: [u8; 16],
    pub display_name: String,
    pub virtual_net: Ipv4Net,
    pub version: u64,
    pub direct_ip: Option<[u8; 4]>,
    pub direct_port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReachEntry {
    pub node_id: [u8; 16],
    pub ip: [u8; 4],
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeighborSyncBody {
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
