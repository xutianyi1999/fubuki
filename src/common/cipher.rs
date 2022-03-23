use aes::cipher::{InnerIvInit, KeyInit, StreamCipher};
use aes::Aes128;
use ctr::{Ctr32BE, CtrCore};

pub struct Aes128Ctr {
    inner_key: Aes128,
    inner: ctr::Ctr32BE<aes::Aes128>,
}

impl Aes128Ctr {
    pub fn new(key: &[u8]) -> Self {
        let mut inner_key = [0u8; 16];
        inner_key.copy_from_slice(md5::compute(key).as_slice());

        let aes = aes::Aes128::new_from_slice(&inner_key).unwrap();
        let core = CtrCore::inner_iv_init(aes.clone(), (&[0u8; 16]).into());

        Aes128Ctr {
            inner: Ctr32BE::from_core(core),
            inner_key: aes,
        }
    }

    #[inline]
    fn in_place(&mut self, data: &mut [u8]) {
        self.inner.apply_keystream(data);
    }

    #[inline]
    pub fn encrypt_slice(&mut self, plaintext_and_ciphertext: &mut [u8]) {
        self.in_place(plaintext_and_ciphertext);
    }

    #[inline]
    pub fn decrypt_slice(&mut self, ciphertext_and_plaintext: &mut [u8]) {
        self.in_place(ciphertext_and_plaintext);
    }
}

impl Clone for Aes128Ctr {
    fn clone(&self) -> Self {
        let core = CtrCore::inner_iv_init(self.inner_key.clone(), (&[0u8; 16]).into());

        Aes128Ctr {
            inner: Ctr32BE::from_core(core),
            inner_key: self.inner_key.clone(),
        }
    }
}
