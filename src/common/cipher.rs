use std::cmp::min;
use std::simd::u8x16;

pub trait Cipher {
    fn encrypt(&self, plaintext_to_ciphertext: &mut [u8], offset: usize);

    fn decrypt(&self, ciphertext_to_plaintext: &mut [u8], offset: usize);
}

#[derive(Clone, Copy)]
pub struct XorCipher {
    key: u8x16,
}

impl Cipher for XorCipher {
    #[inline]
    fn encrypt(&self, mut data: &mut [u8], offset: usize) {
        let v = offset % 16;

        if v != 0 {
            let (l, r) = data.split_at_mut(min(16 - v, data.len()));
            data = r;

            l.iter_mut()
                .zip(&self.key.as_array()[v..])
                .for_each(|(a, b)| *a ^= b);
        }

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
    fn decrypt(&self, ciphertext_to_plaintext: &mut [u8], offset: usize) {
        self.encrypt(ciphertext_to_plaintext, offset)
    }
}

impl TryFrom<&[u8]> for XorCipher {
    type Error = std::io::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let c = XorCipher {
            key: u8x16::from_array(md5::compute(value).0),
        };
        Ok(c)
    }
}

#[test]
fn test() {
    let k = XorCipher::try_from(b"abc".as_ref()).unwrap();
    let mut text = *b"abcdef";

    k.encrypt(&mut text, 0);
    k.decrypt(&mut text[..2], 0);
    k.decrypt(&mut text[2..], 2);

    assert_eq!(&text, b"abcdef");
}
