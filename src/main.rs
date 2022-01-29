#[macro_use]
extern crate log;

use std::env;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::AtomicI64;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use log4rs::append::console::ConsoleAppender;
use log4rs::Config;
use log4rs::config::{Appender, Root};
use log4rs::encode::pattern::PatternEncoder;
use log::LevelFilter;
use mimalloc::MiMalloc;
use serde::Deserialize;
use tokio::fs;
use tokio::runtime::Runtime;

use crate::common::Either;

mod tun;
mod server;
mod client;
mod common;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[derive(Deserialize, Clone)]
struct ServerConfig {
    listen_addr: SocketAddr,
    key: String,
}

#[derive(Deserialize, Clone)]
struct TunConfig {
    ip: Ipv4Addr,
    netmask: Ipv4Addr,
}

#[derive(Deserialize, Clone)]
struct ClientConfig {
    server_addr: String,
    tun: TunConfig,
    key: String,
    direct: bool,
}

fn main() {
    if let Err(e) = launch() {
        error!("Process error -> {:?}", e)
    };
}

fn launch() -> Result<()> {
    logger_init()?;
    let rt = Runtime::new().context("Failed to build tokio runtime")?;

    let res = rt.block_on(async move {
        match load_config().await.context("Failed to load config")? {
            Either::Right(config) => client::start(config).await?,
            Either::Left(config) => server::start(config).await
        }
        Ok(())
    });

    rt.shutdown_background();
    res
}

const INVALID_COMMAND: &str = "Invalid command";

async fn load_config() -> Result<Either<Vec<ServerConfig>, Vec<ClientConfig>>> {
    let mut args = env::args();
    args.next();

    let mode = args.next().ok_or_else(|| anyhow!(INVALID_COMMAND))?;
    let config_path = args.next().ok_or_else(|| anyhow!(INVALID_COMMAND))?;
    let config_json = fs::read_to_string(&config_path).await
        .with_context(|| format!("Failed to read config from: {}", config_path))?;

    let config = match mode.as_str() {
        "client" => {
            let client_config = serde_json::from_str::<Vec<ClientConfig>>(&config_json)
                .context("Failed to parse client config")?;

            Either::Right(client_config)
        }
        "server" => {
            let server_config = serde_json::from_str::<Vec<ServerConfig>>(&config_json)
                .context("Failed to pares server config")?;

            Either::Left(server_config)
        }
        _ => Err(anyhow!(INVALID_COMMAND))?
    };
    Ok(config)
}

fn logger_init() -> Result<()> {
    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new("[Console] {d(%Y-%m-%d %H:%M:%S)} - {l} - {m}{n}")))
        .build();

    let config = Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .build(Root::builder().appender("stdout").build(LevelFilter::Info))?;

    log4rs::init_config(config)?;
    Ok(())
}