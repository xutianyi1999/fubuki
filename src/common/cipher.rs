use std::simd::u8x16;

#[derive(Clone, Copy)]
pub struct XorCipher {
    key: u8x16,
}

impl XorCipher {
    pub fn new(k: &[u8]) -> Self {
        Self {
            key: u8x16::from_array(md5::compute(k).0),
        }
    }

    #[inline]
    fn in_place(&self, mut data: &mut [u8]) {
        while data.len() >= 16 {
            let (l, r) = data.split_array_mut::<16>();
            data = r;
            let new = u8x16::from_array(*l) ^ self.key;
            *l = *new.as_array();
        }

        data.iter_mut()
            .zip(self.key.as_array())
            .for_each(|(a, b)| *a ^= b);
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
