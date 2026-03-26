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
