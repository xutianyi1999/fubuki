use std::process::ExitCode;

use clap::Parser;
use human_panic::setup_panic;

use fubuki::{Args, launch};

#[cfg(not(feature = "gui"))]
fn main() -> ExitCode {
    setup_panic!();

    match launch(Args::parse()) {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{:?}", e);
            ExitCode::FAILURE
        }
    }
}

#[cfg(feature = "gui")]
fn main() -> ExitCode {
    setup_panic!();

    let mut settings = klask::Settings::default();

    if let Ok(path) = std::env::var("FUBUKI_GUI_FONT_PATH") {
        let font = match std::fs::read(path) {
            Ok(font) => font,
            Err(e) => {
                eprintln!("read font data error: {:?}", e);
                return ExitCode::FAILURE;
            }
        };
        settings.custom_font = Some(std::borrow::Cow::Owned(font));
    }

    klask::run_derived::<Args, _>(settings, |args| {
        if let Err(e) = launch(args) {
            eprintln!("{:?}", e);
        }
    });

    ExitCode::SUCCESS
}
