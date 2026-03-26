//! RFC 5389 STUN binding via [`stun_codec`] on the same UDP socket as the mesh.
//! Responses are parsed only when a matching transaction id is in flight (see `runtime`),
//! so unrelated datagrams stay in the FBDC path.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result};
use backon::{ExponentialBuilder, Retryable};
use bytecodec::{DecodeExt, EncodeExt};
use stun_codec::rfc5389::attributes::{MappedAddress, XorMappedAddress};
use stun_codec::rfc5389::{methods::BINDING, Attribute};
use stun_codec::{Message, MessageClass, MessageDecoder, MessageEncoder, TransactionId};

/// Encode a STUN Binding request (transaction id must match the in-flight probe).
pub fn binding_request(tid: [u8; 12]) -> Result<Vec<u8>> {
    let message =
        Message::<Attribute>::new(MessageClass::Request, BINDING, TransactionId::new(tid));
    let mut encoder = MessageEncoder::new();
    encoder
        .encode_into_bytes(message)
        .context("stun encode binding request")
}

/// If `buf` is a Binding success response for `expected_tid`, return XOR-MAPPED / MAPPED IPv4.
pub fn try_parse_binding_response(buf: &[u8], expected_tid: &[u8; 12]) -> Option<(Ipv4Addr, u16)> {
    let mut decoder = MessageDecoder::<Attribute>::new();
    let msg = decoder.decode_from_bytes(buf).ok().and_then(|r| r.ok())?;
    if msg.transaction_id().as_bytes() != expected_tid {
        return None;
    }
    if msg.class() != MessageClass::SuccessResponse {
        return None;
    }
    if msg.method() != BINDING {
        return None;
    }
    let addr = msg
        .get_attribute::<XorMappedAddress>()
        .map(|x| x.address())
        .or_else(|| msg.get_attribute::<MappedAddress>().map(|x| x.address()))?;
    match addr {
        SocketAddr::V4(v) => Some((*v.ip(), v.port())),
        _ => None,
    }
}

pub async fn resolve_stun_server(host_port: &str) -> Option<SocketAddr> {
    let s = host_port.trim();
    let (host, port_s) = s.rsplit_once(':')?;
    let port: u16 = port_s.parse().ok()?;
    let host = host.to_string();
    // Align with previous `exponential-backoff` defaults: 100 ms–10 s, jitter, five lookups.
    let builder = ExponentialBuilder::new()
        .with_min_delay(Duration::from_millis(100))
        .with_max_delay(Duration::from_secs(10))
        .with_max_times(4)
        .with_jitter();
    (|| async {
        match tokio::net::lookup_host((host.as_str(), port)).await {
            Ok(mut addrs) => addrs.next().ok_or(()),
            Err(_) => Err(()),
        }
    })
    .retry(builder)
    .await
    .ok()
}
