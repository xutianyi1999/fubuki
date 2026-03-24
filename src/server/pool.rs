use std::net::Ipv4Addr;
use std::sync::Arc;

use ahash::{HashSet, HashSetExt};
use anyhow::Result;
use ipnet::Ipv4Net;
use parking_lot::Mutex;

use crate::common::net::protocol::AllocateError;

pub(crate) struct AddressPoolInner {
    used: HashSet<Ipv4Addr>,
    cidr: Ipv4Net,
}

impl AddressPoolInner {
    fn new(cidr: Ipv4Net) -> Result<Self> {
        let pool = AddressPoolInner {
            used: HashSet::new(),
            cidr,
        };
        Ok(pool)
    }

    fn get_idle_addr(&mut self) -> Option<Ipv4Addr> {
        self.cidr
            .hosts()
            .find(|&v| !self.used.contains(&v))
    }

    pub(crate) fn release(&mut self, addr: &Ipv4Addr) {
        self.used.remove(addr);
    }
}

pub(crate) struct AddressPool {
    pub(crate) inner: Arc<Mutex<AddressPoolInner>>,
}

impl AddressPool {
    pub(crate) fn new(address_range: Ipv4Net) -> Result<Self> {
        let pool = AddressPool {
            inner: Arc::new(Mutex::new(AddressPoolInner::new(address_range)?)),
        };
        Ok(pool)
    }

    pub(crate) fn get_idle_addr(&self) -> Option<Ipv4Addr> {
        let addr = self.inner.lock().get_idle_addr()?;
        Some(addr)
    }

    pub(crate) fn allocate(&self, ip: Ipv4Addr) -> Result<(), AllocateError> {
        let mut guard = self.inner.lock();

        if !guard.cidr.contains(&ip) {
            return Err(AllocateError::IpNotBelongNetworkRange);
        }

        if guard.cidr.network() == ip {
            return Err(AllocateError::IpSameAsNetworkAddress);
        }

        if guard.cidr.broadcast() == ip {
            return Err(AllocateError::IpSameAsBroadcastAddress);
        }

        if guard.used.contains(&ip) {
            return Err(AllocateError::IpAlreadyInUse);
        }

        guard.used.insert(ip);
        Ok(())
    }
}

pub(crate) struct NoncePool {
    pub(crate) set: Mutex<HashSet<u32>>,
}

impl NoncePool {
    pub(crate) fn new() -> Self {
        Self {
            set: Mutex::new(HashSet::new()),
        }
    }
}
