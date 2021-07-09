#[macro_use]
extern crate log;

use std::env;
use std::error::Error;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};

use crypto::rc4::Rc4;
use log4rs::append::console::ConsoleAppender;
use log4rs::Config;
use log4rs::config::{Appender, Root};
use log4rs::encode::pattern::PatternEncoder;
use log::LevelFilter;
use serde::Deserialize;
use tokio::fs;
use tokio::sync::Notify;

mod tun;
mod server;
mod client;
pub mod common;

pub const COMMAND_FAILED: &str = "Command failed";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    logger_init()?;

    if let Err(e) = process().await {
        error!("Process error -> {}", e)
    };
    Ok(())
}

async fn process() -> Result<(), Box<dyn Error>> {
    let mut args = env::args();
    args.next();

    let mode = args.next().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, COMMAND_FAILED))?;
    let config_path = args.next().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, COMMAND_FAILED))?;

    let json_str = fs::read_to_string(config_path).await?;

    match mode.as_str() {
        "client" => {
            let client_config: ClientConfig = serde_json::from_str(&json_str)?;
            let rc4 = Rc4::new(client_config.key.as_bytes());
            let tun_addr = (client_config.tun.ip, client_config.tun.netmask);
            let buff_capacity = client_config.buff_capacity;

            let res = client::start(
                client_config.server_addr,
                rc4,
                tun_addr,
                buff_capacity,
            ).await;

            info!("Client shutdown");
            res
        }
        "server" => {
            let server_config_vec: Vec<ServerConfig> = serde_json::from_str(&json_str)?;
            let mut list = Vec::with_capacity(server_config_vec.len());

            for server_config in server_config_vec {
                list.push(serve(server_config));
            }

            futures_util::future::join_all(list).await;
            Ok(())
        }
        _ => Err(Box::new(io::Error::new(io::ErrorKind::Other, COMMAND_FAILED)))
    }
}

async fn serve(server_config: ServerConfig) {
    let rc4 = Rc4::new(server_config.key.as_bytes());

    if let Err(e) = server::start(server_config.listen_addr, rc4).await {
        error!("Server handler -> {}", e)
    }
    error!("{} crashed", server_config.listen_addr);
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
    server_addr: SocketAddr,
    tun: TunConfig,
    buff_capacity: usize,
    key: String,
}
