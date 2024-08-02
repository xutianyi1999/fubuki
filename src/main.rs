#![cfg_attr(all(target_os = "windows", feature = "gui"), windows_subsystem = "windows")]

use std::process::ExitCode;
use fubukil::{Args, launch};

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(not(feature = "gui"))]
fn main() -> ExitCode {
    use clap::Parser;

    human_panic::setup_panic!();

    match launch(Args::parse()) {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{:?}", e);
            ExitCode::FAILURE
        }
    }
}

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
#[cfg(feature = "gui")]
fn main() -> ExitCode {
    use font_kit::handle::Handle;
    use std::sync::Arc;

    human_panic::setup_panic!();

    let mut settings = klask::Settings::default();

    let sys_source = font_kit::source::SystemSource::new();

    if let Ok(handle) = sys_source
        .select_best_match(&[font_kit::family_name::FamilyName::Monospace], &font_kit::properties::Properties::new())
    {
        let font = match handle {
            Handle::Memory { bytes, .. } => {
                let bytes = Arc::into_raw(bytes);
                Some(std::borrow::Cow::Borrowed(unsafe { (&*bytes).as_slice() }))
            },
            Handle::Path { path, .. } => match std::fs::read(path) {
                Ok(font) => Some(std::borrow::Cow::Owned(font)),
                _ => None,
            }
        };

        settings.custom_font = font;
    }

    klask::run_derived::<Args, _>(settings, |args| {
        if let Err(e) = launch(args) {
            eprintln!("{:?}", e);
        }
    });

    ExitCode::SUCCESS
}
