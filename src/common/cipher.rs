use std::cmp::min;
use std::simd::u8x32;
use std::sync::Arc;

use chrono::Utc;
use crossbeam_utils::atomic::AtomicCell;
use digest::Digest;
use sha2::Sha256;

pub struct CipherContext<'a> {
    pub offset: usize,
    pub expect_prefix: Option<&'a [u8]>,
    pub key_timestamp: Option<i64>,
}

impl Default for CipherContext<'static> {
    fn default() -> Self {
        CipherContext {
            offset: 0,
            expect_prefix: None,
            key_timestamp: None,
        }
    }
}

pub trait Cipher {
    fn encrypt(&self, plaintext_to_ciphertext: &mut [u8], context: &mut CipherContext);

    fn decrypt(&self, ciphertext_to_plaintext: &mut [u8], context: &mut CipherContext);
}

#[derive(Clone, Copy)]
pub struct XorCipher {
    key: u8x32,
}

impl Cipher for XorCipher {
    fn encrypt(&self, mut data: &mut [u8], context: &mut CipherContext) {
        let offset = context.offset;
        let v = offset % 32;

        if v != 0 {
            let (l, r) = data.split_at_mut(min(32 - v, data.len()));
            data = r;

            l.iter_mut()
                .zip(&self.key.as_array()[v..])
                .for_each(|(a, b)| *a ^= b);
        }

        while data.len() >= 32 {
            let (l, r) = data.split_first_chunk_mut::<32>().unwrap();
            data = r;
            let new = u8x32::from_array(*l) ^ self.key;
            *l = *new.as_array();
        }

        data.iter_mut()
            .zip(self.key.as_array())
            .for_each(|(a, b)| *a ^= b);
    }

    #[inline]
    fn decrypt(&self, ciphertext_to_plaintext: &mut [u8], context: &mut CipherContext) {
        self.encrypt(ciphertext_to_plaintext, context)
    }
}

impl From<&[u8]> for XorCipher {
    fn from(value: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(value);
        let out = hasher.finalize();

        XorCipher {
            key: u8x32::from_slice(out.as_slice())
        }
    }
}

#[derive(Copy, Clone)]
struct TimePeriod<K> {
    timestamp: i64,
    prev: K,
    curr: K,
    next: K,
}

impl<K: for<'a> From<&'a [u8]>> TimePeriod<K> {
    fn build_inner_cipher(key: &[u8; 32], timestamp: i64) -> K {
        let mut input = [0u8; 32 + 8];
        input[..32].copy_from_slice(key);
        input[32..].copy_from_slice(&timestamp.to_be_bytes());
        K::from(&input)
    }

    fn new(
        key: &[u8; 32],
        prev: i64,
        curr: i64,
        next: i64,
    ) -> TimePeriod<K> {
        TimePeriod {
            timestamp: curr,
            prev: Self::build_inner_cipher(key, prev),
            curr: Self::build_inner_cipher(key, curr),
            next: Self::build_inner_cipher(key, next),
        }
    }
}

const PERIOD_SECS: i64 = 60;

#[derive(Clone)]
pub struct RotationCipher<K> {
    key: [u8; 32],
    time_period: Arc<AtomicCell<TimePeriod<K>>>,
    period_secs: i64,
}

impl<K: for<'a> From<&'a [u8]>> From<&[u8]> for RotationCipher<K> {
    fn from(value: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(value);
        let out = hasher.finalize();
        let out: &[u8; 32] = out.as_slice().try_into().unwrap();

        let now = Utc::now().timestamp();
        let curr = now - (now % PERIOD_SECS);

        RotationCipher {
            key: *out,
            time_period: Arc::new(AtomicCell::new(TimePeriod::new(
                out,
                curr - PERIOD_SECS,
                curr,
                curr + PERIOD_SECS,
            ))),
            period_secs: PERIOD_SECS,
        }
    }
}

impl<K: Copy + for<'a> From<&'a [u8]>> RotationCipher<K> {
    fn sync(&self, now: i64) -> TimePeriod<K> {
        let curr = now - (now % self.period_secs);
        let mut tp = self.time_period.load();

        if tp.timestamp != curr {
            tp = TimePeriod::new(
                &self.key,
                curr - self.period_secs,
                curr,
                curr + self.period_secs,
            );
            self.time_period.store(tp);
        }
        tp
    }
}

impl<K: Cipher + Copy + for<'a> From<&'a [u8]>> Cipher for RotationCipher<K> {
    fn encrypt(&self, plaintext_to_ciphertext: &mut [u8], context: &mut CipherContext) {
        let now = Utc::now().timestamp();
        let tp = self.sync(now);
        tp.curr.encrypt(plaintext_to_ciphertext, context);
    }

    fn decrypt(&self, ciphertext_to_plaintext: &mut [u8], context: &mut CipherContext) {
        let now = Utc::now().timestamp();
        let tp = self.sync(now);

        if let Some(key_timestamp) = context.key_timestamp {
            if key_timestamp == tp.timestamp {
                tp.curr.decrypt(ciphertext_to_plaintext, context);
            } else if key_timestamp == tp.timestamp - self.period_secs {
                tp.prev.decrypt(ciphertext_to_plaintext, context);
            } else if key_timestamp == tp.timestamp + self.period_secs {
                tp.next.decrypt(ciphertext_to_plaintext, context);
            }
            return;
        }

        tp.curr.decrypt(ciphertext_to_plaintext, context);
        context.key_timestamp = Some(tp.timestamp);

        if let Some(expect) = context.expect_prefix {
            if expect == &ciphertext_to_plaintext[..expect.len()] {
                return;
            }

            tp.curr.encrypt(ciphertext_to_plaintext, context);

            if now - tp.timestamp < self.period_secs / 2 {
                tp.prev.decrypt(ciphertext_to_plaintext, context);
                context.key_timestamp = Some(tp.timestamp - self.period_secs);
            } else if now - tp.timestamp >= self.period_secs / 2 {
                tp.next.decrypt(ciphertext_to_plaintext, context);
                context.key_timestamp = Some(tp.timestamp + self.period_secs);
            }
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
    fn encrypt(&self, _plaintext_to_ciphertext: &mut [u8], _context: &mut CipherContext) {}

    fn decrypt(&self, _ciphertext_to_plaintext: &mut [u8], _context: &mut CipherContext) {}
}

#[derive(Clone)]
pub enum CipherEnum {
    XorCipher(XorCipher),
    RotationCipher(RotationCipher<XorCipher>),
    NoOpCipher(NoOpCipher),
}

impl Cipher for CipherEnum {
    fn encrypt(&self, plaintext_to_ciphertext: &mut [u8], context: &mut CipherContext) {
        match self {
            CipherEnum::XorCipher(k) => k.encrypt(plaintext_to_ciphertext, context),
            CipherEnum::RotationCipher(k) => k.encrypt(plaintext_to_ciphertext, context),
            CipherEnum::NoOpCipher(k) => k.encrypt(plaintext_to_ciphertext, context),
        }
    }

    fn decrypt(&self, ciphertext_to_plaintext: &mut [u8], context: &mut CipherContext) {
        match self {
            CipherEnum::XorCipher(k) => k.decrypt(ciphertext_to_plaintext, context),
            CipherEnum::RotationCipher(k) => k.decrypt(ciphertext_to_plaintext, context),
            CipherEnum::NoOpCipher(k) => k.decrypt(ciphertext_to_plaintext, context),
        }
    }
}

#[test]
fn test() {
    let k = XorCipher::try_from(b"abc".as_ref()).unwrap();
    let mut text = *b"abcdef";

    k.encrypt(&mut text, &mut CipherContext::default());
    k.decrypt(&mut text[..2], &mut CipherContext::default());
    k.decrypt(&mut text[2..], &mut CipherContext {
        offset: 2,
        expect_prefix: None,
        key_timestamp: None,
    });

    assert_eq!(&text, b"abcdef");
}
