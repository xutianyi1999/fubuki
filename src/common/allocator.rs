use std::cell::RefCell;
use std::mem::MaybeUninit;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

pub struct Bytes {
    inner: Arc<[MaybeUninit<u8>]>,
    start: usize,
    end: usize,
}

unsafe impl Send for Bytes {}

unsafe impl Sync for Bytes {}

impl Deref for Bytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        unsafe {
            MaybeUninit::slice_assume_init_ref(&self.inner[self.start..self.end])
        }
    }
}

impl DerefMut for Bytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe {
            let slice = Arc::get_mut_unchecked(&mut self.inner);
            MaybeUninit::slice_assume_init_mut(&mut slice[self.start..self.end])
        }
    }
}

impl From<&[u8]> for Bytes {
    fn from(value: &[u8]) -> Self {
        let mut new_buff = alloc(value.len());
        new_buff.copy_from_slice(value);
        new_buff
    }
}

impl Bytes {
    pub fn new(len: usize) -> Bytes {
        Bytes {
            inner: Arc::<[u8]>::new_zeroed_slice(len),
            start: 0,
            end: len,
        }
    }

    pub fn split(&mut self, size: usize) -> Bytes {
        assert!(self.start + size <= self.end);

        let new_bytes = Bytes {
            inner: self.inner.clone(),
            start: self.start,
            end: self.start + size,
        };

        self.start += size;
        new_bytes
    }

    pub fn len(&self) -> usize {
        self.end - self.start
    }
}

// 256KB
const BUFFER_SIZE: usize = 262144;
thread_local!(static BUFFER: RefCell<Bytes> = RefCell::new(Bytes::new(BUFFER_SIZE)));

pub fn alloc(size: usize) -> Bytes {
    assert!(size <= BUFFER_SIZE);

    BUFFER.with(|f| {
        let mut guard = f.borrow_mut();

        if guard.len() < size {
            *guard = Bytes::new(BUFFER_SIZE);
        }
        guard.split(size)
    })
}
