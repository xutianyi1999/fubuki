#![feature(impl_trait_in_assoc_type)]

#[cfg(not(any(
    target_os = "windows",
    target_os = "linux",
    target_os = "macos"
)))]
compile_error!("Fubuki only supports Windows, Linux, and macOS.");

#[macro_use]
extern crate log;

mod app;
mod cli;
mod common;
mod dc;
mod platform;

pub use app::launch;
pub use cli::Args;
