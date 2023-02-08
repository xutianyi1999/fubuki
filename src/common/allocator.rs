use std::cell::{RefCell, UnsafeCell};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

pub struct Bytes {
    // todo need optimization
    inner: Arc<UnsafeCell<Box<[u8]>>>,
    start: usize,
    end: usize,
}

unsafe impl Send for Bytes {}

unsafe impl Sync for Bytes {}

impl Deref for Bytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        unsafe {
            &(**self.inner.get())[self.start..self.end]
        }
    }
}

impl DerefMut for Bytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe {
            &mut (**self.inner.get())[self.start..self.end]
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
        let p: Arc<UnsafeCell<Box<[u8]>>> = Arc::from(UnsafeCell::new(vec![0u8; len].into_boxed_slice()));

        Bytes {
            inner: p,
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

// 1MB
const BUFFER_SIZE: usize = 1048576;
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