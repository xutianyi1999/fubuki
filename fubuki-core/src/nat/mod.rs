#[cfg_attr(target_os = "windows", path = "windows.rs")]
#[cfg_attr(target_os = "linux", path = "linux.rs")]
#[cfg_attr(target_os = "macos", path = "macos.rs")]
mod os;

#[allow(unused_imports)]
pub use os::{add_nat, check_available, del_nat};
