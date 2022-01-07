use std::ops::{Deref, DerefMut};
use std::ptr::null_mut;

pub mod persistence;
pub mod net;

pub enum Either<L, R> {
    Right(R),
    Left(L),
}

pub trait Convert<R> {
    fn convert(self) -> R;
}

#[derive(Copy)]
pub struct PointerWrapMut<T> {
    ptr: *mut T,
}

impl<T> PointerWrapMut<T> {
    pub fn new(ptr: &mut T) -> Self {
        PointerWrapMut { ptr }
    }

    pub const fn default() -> Self {
        PointerWrapMut { ptr: null_mut() }
    }
}

impl<T> Deref for PointerWrapMut<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.ptr }
    }
}

impl<T> DerefMut for PointerWrapMut<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.ptr }
    }
}

impl<T> Clone for PointerWrapMut<T> {
    fn clone(&self) -> Self {
        PointerWrapMut { ptr: self.ptr }
    }
}

unsafe impl<T> Send for PointerWrapMut<T> {}

unsafe impl<T> Sync for PointerWrapMut<T> {}