use std::ops::Deref;
use std::ptr::null_mut;

pub mod net;
pub mod persistence;
pub mod rc4;

pub type HashMap<K, V> = std::collections::HashMap<K, V, ahash::RandomState>;
pub type HashSet<V> = std::collections::HashSet<V, ahash::RandomState>;

pub trait MapInit<K, V> {
    fn new() -> HashMap<K, V> {
        Default::default()
    }

    fn with_capacity(capacity: usize) -> HashMap<K, V> {
        HashMap::with_capacity_and_hasher(capacity, Default::default())
    }
}

impl<K, V> MapInit<K, V> for HashMap<K, V> {}

pub trait SetInit<V> {
    fn new() -> HashSet<V> {
        Default::default()
    }

    fn with_capacity(capacity: usize) -> HashSet<V>  {
        HashSet::with_capacity_and_hasher(capacity, Default::default())
    }
}

impl <V> SetInit<V> for HashSet<V>{}

#[derive(Copy, Clone)]
pub struct PointerWrap<T> {
    ptr: *const T,
}

impl<T> PointerWrap<T> {
    pub const fn new(ptr: &T) -> Self {
        PointerWrap { ptr }
    }

    pub const fn null() -> Self {
        PointerWrap { ptr: null_mut() }
    }
}

impl<T> Deref for PointerWrap<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.ptr }
    }
}

unsafe impl<T> Send for PointerWrap<T> {}

unsafe impl<T> Sync for PointerWrap<T> {}
