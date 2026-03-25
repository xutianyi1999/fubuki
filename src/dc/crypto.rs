use anyhow::{anyhow, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

pub struct DcKeys {
    pub k_control: [u8; 32],
    pub k_data: [u8; 32],
}

impl DcKeys {
    pub fn derive(psk: &[u8], network_id: &[u8; 16]) -> Result<Self> {
        let hk = Hkdf::<Sha256>::new(Some(network_id), psk);

        let mut k_control = [0u8; 32];
        let mut info_ctrl = Vec::with_capacity(7 + 22 + 16);
        info_ctrl.extend_from_slice(b"control");
        info_ctrl.extend_from_slice(b"fubuki-dc/v1/network");
        info_ctrl.extend_from_slice(network_id);
        hk.expand(&info_ctrl, &mut k_control)
            .map_err(|_| anyhow!("HKDF expand k_control"))?;

        let mut k_data = [0u8; 32];
        let mut info_data = Vec::with_capacity(4 + 22 + 16);
        info_data.extend_from_slice(b"data");
        info_data.extend_from_slice(b"fubuki-dc/v1/network");
        info_data.extend_from_slice(network_id);
        hk.expand(&info_data, &mut k_data)
            .map_err(|_| anyhow!("HKDF expand k_data"))?;

        Ok(DcKeys { k_control, k_data })
    }
}

/// 12-byte AEAD nonce from outer u64 + msg_type (spec: unique per sender stream).
pub fn aead_nonce(outer_nonce: u64, msg_type: u16) -> Nonce {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&outer_nonce.to_le_bytes());
    n[8..10].copy_from_slice(&msg_type.to_le_bytes());
    Nonce::from(n)
}

pub fn build_aad(magic: &[u8; 4], proto_version: u16, msg_type: u16, sender: &[u8; 16], nonce: u64) -> [u8; 32] {
    let mut a = [0u8; 32];
    a[0..4].copy_from_slice(magic);
    a[4..6].copy_from_slice(&proto_version.to_be_bytes());
    a[6..8].copy_from_slice(&msg_type.to_be_bytes());
    a[8..24].copy_from_slice(sender);
    a[24..32].copy_from_slice(&nonce.to_le_bytes());
    a
}

pub fn encrypt(
    key: &[u8; 32],
    aad: &[u8],
    outer_nonce: u64,
    msg_type: u16,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = aead_nonce(outer_nonce, msg_type);
    cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow!("chacha encrypt"))
}

pub fn decrypt(
    key: &[u8; 32],
    aad: &[u8],
    outer_nonce: u64,
    msg_type: u16,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = aead_nonce(outer_nonce, msg_type);
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow!("chacha decrypt"))
}
