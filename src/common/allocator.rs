use std::mem::MaybeUninit;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use parking_lot::RwLock;

pub struct Bytes {
    inner: Arc<[MaybeUninit<u8>]>,
    start: AtomicUsize,
    end: usize,
}

unsafe impl Send for Bytes {}

unsafe impl Sync for Bytes {}

impl Deref for Bytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        unsafe {
            MaybeUninit::slice_assume_init_ref(&self.inner[self.start.load(Ordering::Relaxed)..self.end])
        }
    }
}

impl DerefMut for Bytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe {
            let slice = Arc::get_mut_unchecked(&mut self.inner);
            MaybeUninit::slice_assume_init_mut(&mut slice[*self.start.get_mut()..self.end])
        }
    }
}

impl Bytes {
    pub fn new(len: usize) -> Bytes {
        Bytes {
            inner: Arc::<[u8]>::new_zeroed_slice(len),
            start: AtomicUsize::new(0),
            end: len,
        }
    }

    pub fn split(&self, size: usize) -> Result<Bytes, usize> {
        let mut start = self.start.load(Ordering::Relaxed);

        loop {
            let new_start = start + size;
            let end = self.end;

            if new_start > end {
                return Err(new_start);
            }

            if let Err(v) = self.start.compare_exchange_weak(start, new_start, Ordering::Relaxed, Ordering::Relaxed) {
                start = v;
                continue;
            }

            let new_bytes = Bytes {
                inner: self.inner.clone(),
                start: AtomicUsize::new(start),
                end: new_start,
            };

            return Ok(new_bytes);
        }
    }

    pub fn split_mut(&mut self, size: usize) -> Result<Bytes, usize> {
        let start = self.start.get_mut();
        let new_start = *start + size;
        let end = self.end;

        if new_start > end {
            return Err(new_start);
        }

        let new_bytes = Bytes {
            inner: self.inner.clone(),
            start: AtomicUsize::new(*start),
            end: new_start,
        };

        *start = new_start;
        return Ok(new_bytes);
    }

    #[allow(unused)]
    pub fn len(&self) -> usize {
        self.end - self.start.load(Ordering::Relaxed)
    }
}

// 256KB
const BUFFER_SIZE: usize = 262144;
static BUFFER: RwLock<Option<Bytes>> = RwLock::new(None);

pub fn alloc(size: usize) -> Bytes {
    assert!(size <= BUFFER_SIZE);

    {
        let guard = BUFFER.read();

        if let Some(v) = &*guard {
            if let Ok(b) = v.split(size) {
                return b;
            }
        };
    }

    let mut guard = BUFFER.write();
    let buff = &mut *guard;

    if let Some(v) = &mut *buff {
        if let Ok(v) = v.split_mut(size)  {
            return v;
        }
    }

    let mut bytes = Bytes::new(BUFFER_SIZE);
    let new_bytes = bytes.split_mut(size).unwrap();
    *buff = Some(bytes);
    new_bytes
}

#[test]
fn test() {
    let buf = alloc(10);
    assert_eq!(buf.len(), 10);

    let buf2 = buf.split(7).unwrap();
    assert_eq!(buf2.len(), 7);
    assert_eq!(buf.len(), 3);

    let mut buf3 = buf.split(3).unwrap();
    assert_eq!(buf3.len(), 3);
    assert_eq!(buf.len(), 0);
    println!("{:?}", buf.deref());

    let buf4 = buf3.split_mut(2).unwrap();
    assert_eq!(buf4.len(), 2);
    assert_eq!(buf3.len(), 1);
}