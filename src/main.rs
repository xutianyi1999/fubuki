#[macro_use]
extern crate log;

use std::env;
use std::net::{IpAddr, SocketAddr};

use crypto::rc4::Rc4;
use log4rs::append::console::ConsoleAppender;
use log4rs::Config;
use log4rs::config::{Appender, Root};
use log4rs::encode::pattern::PatternEncoder;
use log::LevelFilter;
use serde::Deserialize;
use tokio::fs;
use tokio::io::{Error, ErrorKind, Result};
use tokio::sync::Notify;

use crate::common::res::{OptionConvert, StdResAutoConvert};

mod tun;
mod server;
mod client;
pub mod common;

pub const COMMAND_FAILED: &str = "Command failed";

#[tokio::main]
async fn main() -> Result<()> {
    logger_init()?;

    if let Err(e) = process().await {
        error!("process error -> {}", e)
    };
    Ok(())
}

async fn process() -> Result<()> {
    let mut args = env::args();
    args.next();

    let mode = args.next().option_to_res(COMMAND_FAILED)?;
    let config_path = args.next().option_to_res(COMMAND_FAILED)?;

    let json_str = fs::read_to_string(config_path).await?;

    match mode.as_str() {
        "client" => {
            let client_config: ClientConfig = serde_json::from_str(&json_str)?;
            let rc4 = Rc4::new(client_config.key.as_bytes());
            let tun_addr = (client_config.tun.ip, client_config.tun.netmask);
            let buff_capacity = client_config.buff_capacity;

            client::start(client_config.server_addr, rc4, tun_addr, buff_capacity).await
        }
        "server" => {
            let server_config_vec: Vec<ServerConfig> = serde_json::from_str(&json_str)?;

            for server_config in server_config_vec {
                tokio::spawn(async move {
                    let rc4 = Rc4::new(server_config.key.as_bytes());

                    if let Err(e) = server::start(server_config.listen_addr, rc4).await {
                        error!("{}", e)
                    }
                });
            }

            Notify::new().notified().await;
            Ok(())
        }
        _ => Err(Error::new(ErrorKind::Other, COMMAND_FAILED))
    }
}

fn logger_init() -> Result<()> {
    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new("[Console] {d(%Y-%m-%d %H:%M:%S)} - {l} - {m}{n}")))
        .build();

    let config = Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .build(Root::builder().appender("stdout").build(LevelFilter::Info))
        .res_auto_convert()?;

    log4rs::init_config(config).res_auto_convert()?;
    Ok(())
}

#[derive(Deserialize, Clone)]
struct ServerConfig {
    listen_addr: SocketAddr,
    key: String,
}

#[derive(Deserialize, Clone)]
struct TunConfig {
    ip: IpAddr,
    netmask: IpAddr,
}

#[derive(Deserialize, Clone)]
struct ClientConfig {
    server_addr: SocketAddr,
    tun: TunConfig,
    buff_capacity: usize,
    key: String,
}
