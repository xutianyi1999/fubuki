#[macro_use]
extern crate log;

use std::env;
use std::error::Error;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};

use log4rs::append::console::ConsoleAppender;
use log4rs::Config;
use log4rs::config::{Appender, Root};
use log4rs::encode::pattern::PatternEncoder;
use log::LevelFilter;
use serde::Deserialize;
use tokio::fs;

use crate::common::Either;

mod tun;
mod server;
mod client;
mod common;

#[derive(Deserialize, Clone)]
struct ServerConfig {
    listen_addr: SocketAddr,
    key: String,
}

#[derive(Deserialize, Clone)]
struct TunAdapter {
    ip: Ipv4Addr,
    netmask: Ipv4Addr,
}

#[derive(Deserialize, Clone)]
struct ClientConfig {
    server_addr: SocketAddr,
    tun: TunAdapter,
    key: String,
    is_direct: bool,
}

#[tokio::main]
async fn main() {
    if let Err(e) = launch().await {
        error!("Process error -> {}", e)
    };
}

async fn launch() -> Result<(), Box<dyn Error>> {
    logger_init().unwrap();

    match load_config().await? {
        Either::Right(config) => client::start(config).await?,
        Either::Left(config) => server::start(config).await
    };
    Ok(())
}

const INVALID_COMMAND: &str = "Invalid command";

async fn load_config() -> Result<Either<Vec<ServerConfig>, ClientConfig>, Box<dyn Error>> {
    let mut args = env::args();
    args.next();

    let mode = args.next().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, INVALID_COMMAND))?;
    let config_path = args.next().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, INVALID_COMMAND))?;
    let config_json = fs::read_to_string(config_path).await?;

    let config = match mode.as_str() {
        "client" => {
            let client_config = serde_json::from_str::<ClientConfig>(&config_json)?;
            Either::Right(client_config)
        }
        "server" => {
            let server_config = serde_json::from_str::<Vec<ServerConfig>>(&config_json)?;
            Either::Left(server_config)
        }
        _ => return Err(Box::new(io::Error::new(io::ErrorKind::InvalidInput, INVALID_COMMAND)))
    };
    Ok(config)
}

fn logger_init() -> Result<(), Box<dyn Error>> {
    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new("[Console] {d(%Y-%m-%d %H:%M:%S)} - {l} - {m}{n}")))
        .build();

    let config = Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .build(Root::builder().appender("stdout").build(LevelFilter::Info))?;

    log4rs::init_config(config)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use chrono::{DateTime, Utc};

    struct User {
        name: String,
        age: i32,
    }

    #[test]
    fn a1() {
        let user = User { name: "abc".to_string(), age: 10 };
        let arr = [0u8; 32];
        let p = &arr[..];

        let a = Box::<[u8]>::from(p);
    }
}