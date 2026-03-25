//! Decentralized mesh (FBDC): PSK, UDP directory gossip, TUN data plane.
//! See `doc/decentralized-mvp.md`.
//!
//! Control-plane gossip sends [`MEMBER_ANNOUNCE`](msg::MEMBER_ANNOUNCE) and optional [`NEIGHBOR_SYNC`](msg::NEIGHBOR_SYNC).
//! Fan-out uses a bounded [`lru::LruCache`] peer set; off-the-shelf
//! gossip membership stacks assume their own wire format and do not speak FBDC.
//!
//! STUN ([`stun_codec`], same UDP socket) + [`NEIGHBOR_SYNC`](msg::NEIGHBOR_SYNC) spread reflexive
//! endpoints and observed underlay (`direct_udp`) so LAN / single-seed meshes converge.
//! Plaintext `PCH\x01` probes hole-punch to those endpoints.

mod config;
mod crypto;
mod directory;
mod frame;
mod msg;
mod row_version;
mod runtime;
mod stun;

pub use runtime::run;
