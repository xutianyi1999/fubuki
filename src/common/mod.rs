pub mod cipher;
pub mod net;
pub mod persistence;

#[macro_export]
macro_rules! ternary {
    ($condition: expr, $_true: expr, $_false: expr) => {
        if $condition {
            $_true
        } else {
            $_false
        }
    };
}

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

    fn with_capacity(capacity: usize) -> HashSet<V> {
        HashSet::with_capacity_and_hasher(capacity, Default::default())
    }
}

impl<V> SetInit<V> for HashSet<V> {}
