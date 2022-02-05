use std::ops::{Deref, DerefMut};
use std::ptr::null_mut;

pub mod persistence;
pub mod net;
pub mod rc4;

pub type HashMap<K, V> = std::collections::HashMap<K, V, ahash::RandomState>;

pub enum Either<L, R> {
    Right(R),
    Left(L),
}

pub trait Convert<R> {
    fn convert(self) -> R;
}

#[derive(Copy)]
pub struct PointerWrap<T> {
    ptr: *const T,
}

impl<T> PointerWrap<T> {
    pub fn new(ptr: &T) -> Self {
        PointerWrap { ptr }
    }

    pub const fn default() -> Self {
        PointerWrap { ptr: null_mut() }
    }
}

impl<T> Deref for PointerWrap<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.ptr }
    }
}

impl<T> Clone for PointerWrap<T> {
    fn clone(&self) -> Self {
        PointerWrap { ptr: self.ptr }
    }
}

unsafe impl<T> Send for PointerWrap<T> {}

unsafe impl<T> Sync for PointerWrap<T> {}