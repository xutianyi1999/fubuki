//! FBDC outer UDP frame (see `doc/decentralized-architecture.md` §3.2).

pub const MAGIC: [u8; 4] = *b"FBDC";
pub const PROTO_VERSION: u16 = 1;
pub const HEADER_LEN: usize = 34;

pub fn encode(
    msg_type: u16,
    sender: &[u8; 16],
    nonce: u64,
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    v.extend_from_slice(&MAGIC);
    v.extend_from_slice(&PROTO_VERSION.to_be_bytes());
    v.extend_from_slice(&msg_type.to_be_bytes());
    v.extend_from_slice(sender);
    v.extend_from_slice(&nonce.to_le_bytes());
    debug_assert!(ciphertext.len() <= u16::MAX as usize);
    v.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
    v.extend_from_slice(ciphertext);
    v
}

#[derive(Debug)]
pub struct ParsedFrame<'a> {
    pub msg_type: u16,
    pub sender: [u8; 16],
    pub nonce: u64,
    pub ciphertext: &'a [u8],
}

pub fn decode(buf: &[u8]) -> Option<ParsedFrame<'_>> {
    if buf.len() < HEADER_LEN {
        return None;
    }
    if buf[0..4] != MAGIC {
        return None;
    }
    let proto = u16::from_be_bytes([buf[4], buf[5]]);
    if proto != PROTO_VERSION {
        return None;
    }
    let msg_type = u16::from_be_bytes([buf[6], buf[7]]);
    let mut sender = [0u8; 16];
    sender.copy_from_slice(&buf[8..24]);
    let nonce = u64::from_le_bytes(buf[24..32].try_into().ok()?);
    let ct_len = u16::from_be_bytes([buf[32], buf[33]]) as usize;
    if buf.len() < HEADER_LEN + ct_len {
        return None;
    }
    let ciphertext = &buf[HEADER_LEN..HEADER_LEN + ct_len];
    Some(ParsedFrame {
        msg_type,
        sender,
        nonce,
        ciphertext,
    })
}
