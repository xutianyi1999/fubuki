mod types;
mod routing;
mod packet;
mod runtime;

mod api;
#[cfg(feature = "cross-nat")]
mod cross_nat;
#[cfg_attr(any(target_os = "windows", target_os = "linux", target_os = "macos"), path = "sys_route.rs")]
#[cfg_attr(not(any(target_os = "windows", target_os = "linux", target_os = "macos")), path = "fake_sys_route.rs")]
mod sys_route;
mod info_tui;

pub use types::{Direction, Interface, InterfaceInfo};
#[allow(unused_imports)]
pub use runtime::{
    generic_interfaces_info, info, interfaces_info_query, packet_send, start,
};
