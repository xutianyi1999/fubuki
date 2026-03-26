use std::net::Ipv4Addr;

use anyhow::{anyhow, Result};

/// Minimum IPv4 header length (no options).
const IPV4_HDR_MIN: usize = 20;

/// Parse source IPv4 from a raw IPv4 packet (starts at IP header).
pub fn get_ip_src_addr(packet: &[u8]) -> Result<Ipv4Addr> {
    Ok(parse_ipv4_addrs(packet)?.0)
}

/// Parse destination IPv4 from a raw IPv4 packet.
pub fn get_ip_dst_addr(packet: &[u8]) -> Result<Ipv4Addr> {
    Ok(parse_ipv4_addrs(packet)?.1)
}

fn parse_ipv4_addrs(packet: &[u8]) -> Result<(Ipv4Addr, Ipv4Addr)> {
    if packet.len() < IPV4_HDR_MIN {
        return Err(anyhow!(
            "packet too short for IPv4 header: {} bytes",
            packet.len()
        ));
    }
    let vihl = packet[0];
    let version = vihl >> 4;
    if version != 4 {
        return Err(anyhow!("not an IPv4 packet (version {version})"));
    }
    let ihl = (vihl & 0x0f) as usize * 4;
    if ihl < IPV4_HDR_MIN || ihl > packet.len() {
        return Err(anyhow!("invalid IPv4 IHL: {ihl}"));
    }
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    Ok((src, dst))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    /// Minimal IPv4 header (20 B): version 4, IHL 5, total length ignored, src/dst set.
    fn sample_packet(src: Ipv4Addr, dst: Ipv4Addr) -> [u8; 28] {
        let mut p = [0u8; 28];
        p[0] = 0x45;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        p
    }

    #[test]
    fn parse_src_dst_roundtrip() {
        let s = Ipv4Addr::new(10, 0, 0, 1);
        let d = Ipv4Addr::new(10, 200, 1, 5);
        let p = sample_packet(s, d);
        assert_eq!(get_ip_src_addr(&p).unwrap(), s);
        assert_eq!(get_ip_dst_addr(&p).unwrap(), d);
        assert_eq!(parse_ipv4_addrs(&p).unwrap(), (s, d));
    }

    #[test]
    fn rejects_too_short() {
        assert!(get_ip_src_addr(&[0u8; 19]).is_err());
    }

    #[test]
    fn rejects_non_ipv4_version() {
        let mut p = sample_packet(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST);
        p[0] = 0x65;
        assert!(parse_ipv4_addrs(&p).is_err());
    }

    #[test]
    fn rejects_ihl_too_small() {
        let mut p = sample_packet(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST);
        p[0] = 0x41;
        assert!(parse_ipv4_addrs(&p).is_err());
    }

    #[test]
    fn rejects_ihl_past_buffer() {
        let mut p = sample_packet(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST);
        p[0] = 0x4f;
        assert!(parse_ipv4_addrs(&p).is_err());
    }
}
