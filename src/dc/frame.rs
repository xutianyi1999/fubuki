//! FBDC outer UDP frame (see `doc/decentralized-architecture.md` §3.2).

pub const MAGIC: [u8; 4] = *b"FBDC";
pub const PROTO_VERSION: u16 = 1;
pub const HEADER_LEN: usize = 34;

pub fn encode(msg_type: u16, sender: &[u8; 16], nonce: u64, ciphertext: &[u8]) -> Vec<u8> {
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

/// Parsed FBDC UDP datagram header plus ciphertext slice (see module constants for layout).
#[derive(Debug)]
pub struct ParsedFrame<'a> {
    /// Application message discriminant ([`super::msg`] constants).
    pub msg_type: u16,
    /// Sender `node_id` (16 bytes, usually a UUID).
    pub sender: [u8; 16],
    /// Outer nonce; combined with `msg_type` for AEAD nonce uniqueness.
    pub nonce: u64,
    /// Encrypted inner payload (bincode [`super::msg::Inner`] for control types).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let sender = *b"abcdefghijklmnop";
        let ct = [0xab, 0xcd];
        let buf = encode(42, &sender, 0x1122_3344_5566_7788, &ct);
        let p = decode(&buf).expect("decode");
        assert_eq!(p.msg_type, 42);
        assert_eq!(p.sender, sender);
        assert_eq!(p.nonce, 0x1122_3344_5566_7788);
        assert_eq!(p.ciphertext, ct.as_slice());
    }

    #[test]
    fn decode_rejects_bad_magic() {
        let mut buf = encode(1, &[9u8; 16], 0, &[]);
        buf[0] = b'X';
        assert!(decode(&buf).is_none());
    }

    #[test]
    fn decode_rejects_wrong_proto() {
        let mut buf = encode(1, &[9u8; 16], 0, &[]);
        buf[4..6].copy_from_slice(&999u16.to_be_bytes());
        assert!(decode(&buf).is_none());
    }

    #[test]
    fn decode_rejects_truncated() {
        assert!(decode(&[]).is_none());
        let buf = encode(1, &[9u8; 16], 0, &[1, 2, 3]);
        assert!(decode(&buf[..buf.len() - 1]).is_none());
    }
}
