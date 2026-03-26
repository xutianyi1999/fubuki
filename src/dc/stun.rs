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

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    use bytecodec::{DecodeExt, EncodeExt};
    use stun_codec::rfc5389::attributes::MappedAddress;
    use stun_codec::rfc5389::{methods::BINDING, Attribute};
    use stun_codec::{Message, MessageClass, MessageDecoder, MessageEncoder, TransactionId};

    use super::{binding_request, resolve_stun_server, try_parse_binding_response};

    fn sample_binding_success(tid: [u8; 12], mapped: SocketAddr) -> Vec<u8> {
        let mut msg = Message::<Attribute>::new(
            MessageClass::SuccessResponse,
            BINDING,
            TransactionId::new(tid),
        );
        msg.add_attribute(MappedAddress::new(mapped));
        MessageEncoder::new()
            .encode_into_bytes(msg)
            .expect("stun encode response")
    }

    #[test]
    fn binding_request_encodes() {
        let tid = [0xabu8; 12];
        let req = binding_request(tid).expect("binding_request");
        assert!(req.len() >= 20);
        let mut dec = MessageDecoder::<Attribute>::new();
        let msg = dec.decode_from_bytes(&req).expect("decode").expect("frame");
        assert_eq!(msg.class(), MessageClass::Request);
        assert_eq!(msg.method(), BINDING);
        assert_eq!(msg.transaction_id().as_bytes(), &tid);
    }

    #[test]
    fn try_parse_binding_success_ipv4() {
        let tid = [7u8; 12];
        let mapped = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 2), 43000));
        let bytes = sample_binding_success(tid, mapped);
        let got = try_parse_binding_response(&bytes, &tid).expect("parsed");
        assert_eq!(got.0, Ipv4Addr::new(198, 51, 100, 2));
        assert_eq!(got.1, 43000);
    }

    #[test]
    fn try_parse_wrong_transaction_id() {
        let tid = [1u8; 12];
        let wrong = [2u8; 12];
        let bytes = sample_binding_success(
            tid,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9)),
        );
        assert!(try_parse_binding_response(&bytes, &wrong).is_none());
    }

    #[tokio::test]
    async fn resolve_stun_rejects_bad_host_port() {
        assert!(resolve_stun_server("no-colon").await.is_none());
        assert!(resolve_stun_server("host:notaport").await.is_none());
    }
}
