use std::str::FromStr;

use anyhow::Result;
use log::LevelFilter;
use tokio::runtime::Runtime;

use crate::cli::{Args, Command};

pub(crate) fn logger_init() -> Result<()> {
    fn init() -> Result<()> {
        use log4rs::append::console::ConsoleAppender;
        use log4rs::config::{Appender, Root};
        use log4rs::encode::pattern::PatternEncoder;

        let log_level = LevelFilter::from_str(
            std::env::var("FUBUKI_LOG").as_deref().unwrap_or("INFO"),
        )?;

        let pattern = if log_level >= LevelFilter::Debug {
            "[{d(%Y-%m-%d %H:%M:%S)}] {h({l})} {f}:{L} - {m}{n}"
        } else {
            "[{d(%Y-%m-%d %H:%M:%S)}] {h({l})} {t} - {m}{n}"
        };

        let stdout = ConsoleAppender::builder()
            .encoder(Box::new(PatternEncoder::new(pattern)))
            .build();

        let config = log4rs::Config::builder()
            .appender(Appender::builder().build("stdout", Box::new(stdout)))
            .build(Root::builder().appender("stdout").build(log_level))?;

        log4rs::init_config(config)?;
        Ok(())
    }

    static LOGGER_INIT: std::sync::Once = std::sync::Once::new();

    LOGGER_INIT.call_once(|| {
        init().expect("Logger initialization failed.");
    });
    Ok(())
}

pub fn launch(args: Args) -> Result<()> {
    logger_init()?;

    match args.command {
        Command::Daemon { config_path } => {
            crate::common::privilege::require_elevated_for_node()?;
            let rt = Runtime::new()?;
            rt.block_on(crate::dc::run(&config_path))?;
        }
        Command::Update {
            repo_owner,
            repo_name,
        } => {
            let status = self_update::backends::github::Update::configure()
                .repo_owner(&repo_owner)
                .repo_name(&repo_name)
                .bin_name("fubuki")
                .show_download_progress(true)
                .show_output(true)
                .current_version(self_update::cargo_crate_version!())
                .build()?
                .update()?;

            println!("{}", status);
        }
    }
    Ok(())
}
