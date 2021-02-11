#[macro_use]
extern crate log;

use std::env;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use crypto::rc4::Rc4;
use log4rs::append::console::ConsoleAppender;
use log4rs::Config;
use log4rs::config::{Appender, Root};
use log4rs::encode::pattern::PatternEncoder;
use log::LevelFilter;
use tokio::io::{Error, ErrorKind, Result};

use crate::common::res::{OptionConvert, StdResAutoConvert};

mod tun;
mod server;
mod client;
pub mod common;

pub const COMMAND_FAILED: &str = "Command failed";

#[tokio::main]
async fn main() -> Result<()> {
    logger_init()?;

    let mut args = env::args();
    let mode = args.next().option_to_res(COMMAND_FAILED)?;

    let server_addr = SocketAddr::from_str("0.0.0.0:12333").unwrap();
    let rc4 = Rc4::new(b"abc");

    match mode.as_str() {
        "client" => {
            let listen_addr = SocketAddr::from_str("0.0.0.0:12345").unwrap();
            let tun_addr = (IpAddr::from([10, 0, 0, 2]), IpAddr::from([255, 255, 255, 0]));
            let name = "a1";
            client::start(listen_addr, server_addr, rc4, tun_addr, name).await
        }
        "server" => {
            server::start(server_addr, rc4).await
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
