use std::simd::u8x16;

#[derive(Clone, Copy)]
pub struct XorCipher {
    key: u8x16,
}

impl XorCipher {
    pub fn new(k: &[u8]) -> Self {
        let mut key = [0u8; 16];
        key.copy_from_slice(md5::compute(k).as_slice());

        Self {
            key: u8x16::from_array(key),
        }
    }

    #[inline]
    fn in_place(&self, data: &mut [u8]) {
        let count = data.len() / 16;

        for i in 0..count {
            let range = &mut data[i * 16..(i + 1) * 16];
            let m1: u8x16 = u8x16::from_slice(range);
            range.copy_from_slice((m1 ^ self.key).as_array())
        }

        for (i, v) in data[count * 16..].iter_mut().enumerate() {
            *v ^= self.key.as_array()[i]
        }
    }

    #[inline]
    pub fn encrypt_slice(&self, plaintext_and_ciphertext: &mut [u8]) {
        self.in_place(plaintext_and_ciphertext);
    }

    #[inline]
    pub fn decrypt_slice(&self, ciphertext_and_plaintext: &mut [u8]) {
        self.in_place(ciphertext_and_plaintext);
    }
}
