use std::cmp::min;
use std::simd::u8x32;

pub struct CipherContext {
    pub offset: usize,
    pub nonce: u16
}

impl Default for CipherContext {
    fn default() -> Self {
        CipherContext {
            offset: 0,
            nonce: 0
        }
    }
}

pub trait Cipher {
    fn encrypt(&self, plaintext_to_ciphertext: &mut [u8], context: &CipherContext);

    fn decrypt(&self, ciphertext_to_plaintext: &mut [u8], context: &CipherContext);
}

#[derive(Clone, Copy)]
pub struct XorCipher {
    basekey: [u8; 32],
}

fn key_mix(base_key: &mut [u8; 32], nonce: u8) {
    for x in base_key {
        *x ^= nonce;
    }
}

impl Cipher for XorCipher {
    fn encrypt(&self, mut data: &mut [u8], context: &CipherContext) {
        let mut key = self.basekey;
        let nonce: [u8; 2] = context.nonce.to_be_bytes();
        key_mix(&mut key, nonce[0] ^ nonce[1]);
        let key = u8x32::from_array(key);

        let offset = context.offset;
        let v = offset % 32;

        if v != 0 {
            let (l, r) = data.split_at_mut(min(32 - v, data.len()));
            data = r;

            l.iter_mut()
                .zip(&key.as_array()[v..])
                .for_each(|(a, b)| *a ^= b);
        }

        while data.len() >= 32 {
            let (l, r) = data.split_first_chunk_mut::<32>().unwrap();
            data = r;
            let new = u8x32::from_array(*l) ^ key;
            *l = *new.as_array();
        }

        data.iter_mut()
            .zip(key.as_array())
            .for_each(|(a, b)| *a ^= b);
    }

    #[inline]
    fn decrypt(&self, ciphertext_to_plaintext: &mut [u8], context: &CipherContext) {
        self.encrypt(ciphertext_to_plaintext, context)
    }
}

impl From<&[u8]> for XorCipher {
    fn from(value: &[u8]) -> Self {
        let out = blake3::hash(value);

        XorCipher {
            basekey: *out.as_bytes()
        }
    }
}

#[derive(Copy, Clone)]
pub struct NoOpCipher {}

impl From<&[u8]> for NoOpCipher {
    fn from(_: &[u8]) -> Self {
        NoOpCipher {}
    }
}

impl Cipher for NoOpCipher {
    fn encrypt(&self, _plaintext_to_ciphertext: &mut [u8], _context: &CipherContext) {}

    fn decrypt(&self, _ciphertext_to_plaintext: &mut [u8], _context: &CipherContext) {}
}

#[derive(Clone)]
pub enum CipherEnum {
    XorCipher(XorCipher),
    NoOpCipher(NoOpCipher),
}

impl Cipher for CipherEnum {
    fn encrypt(&self, plaintext_to_ciphertext: &mut [u8], context: &CipherContext) {
        match self {
            CipherEnum::XorCipher(k) => k.encrypt(plaintext_to_ciphertext, context),
            CipherEnum::NoOpCipher(k) => k.encrypt(plaintext_to_ciphertext, context),
        }
    }

    fn decrypt(&self, ciphertext_to_plaintext: &mut [u8], context: &CipherContext) {
        match self {
            CipherEnum::XorCipher(k) => k.decrypt(ciphertext_to_plaintext, context),
            CipherEnum::NoOpCipher(k) => k.decrypt(ciphertext_to_plaintext, context),
        }
    }
}

#[test]
fn test() {
    let k = XorCipher::from(b"abc".as_ref());
    let mut text = *b"abcdef";

    k.encrypt(&mut text, &CipherContext::default());
    k.decrypt(&mut text[..2], &CipherContext::default());
    k.decrypt(&mut text[2..], &CipherContext {
        offset: 2,
        nonce: 0
    });

    assert_eq!(&text, b"abcdef");
}
