use std::io::{Error, Result};
use std::sync::Arc;

use crate::TunIpAddr;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

pub trait TunDevice: Send + Sync {
    fn send_packet(&self, packet: &[u8]) -> Result<()>;

    fn recv_packet(&self, buff: &mut [u8]) -> Result<usize>;
}

impl<T: TunDevice> TunDevice for Arc<T> {
    fn send_packet(&self, packet: &[u8]) -> Result<()> {
        (**self).send_packet(packet)
    }

    fn recv_packet(&self, buff: &mut [u8]) -> Result<usize> {
        (**self).recv_packet(buff)
    }
}

pub(crate) fn create_device(mtu: usize, ip_addrs: &[TunIpAddr]) -> Result<impl TunDevice> {
    #[cfg(target_os = "windows")]
    {
        windows::Wintun::create(mtu, ip_addrs)
    }
    #[cfg(target_os = "linux")]
    {
        linux::Linuxtun::create(mtu, ip_addrs)
    }
    #[cfg(target_os = "macos")]
    {
        macos::Macostun::create(mtu, ip_addrs)
    }
}

pub(crate) fn skip_error(err: &Error) -> bool {
    if cfg!(target_os = "linux") {
        const INVALID_ARGUMENT: i32 = 22;
        err.raw_os_error() == Some(INVALID_ARGUMENT)
    } else {
        false
    }
}
