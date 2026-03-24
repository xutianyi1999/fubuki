use std::ffi::c_void;
use std::path::Path;
use std::str::FromStr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock};

use anyhow::{anyhow, Context as AnyhowContext, Result};
use flume;
use log::LevelFilter;
use serde::de;
use tokio::runtime::Runtime;

use crate::cli::{Args, NodeCmd, ServerCmd};
use crate::common::allocator::Bytes;
use crate::node::{Direction, Interface};
use crate::{common, node, server, tun, Key, NodeConfig, NodeConfigFinalize, ServerConfig, ServerConfigFinalize, SHOULD_RESTART};

pub struct Context<K> {
    pub interfaces: Option<Arc<OnceLock<Vec<Arc<Interface<K>>>>>>,
    pub send_packet_chan: Option<flume::Sender<(Direction, Bytes)>>,
}

#[repr(C)]
pub struct ExternalContext {
    pub ctx: *const c_void,
    pub interfaces_info_fn: *const c_void,
    pub packet_send_fn: *const c_void,
}

pub(crate) fn restart() -> ! {
    let exe = std::env::current_exe().expect("failed to get current executable path");
    let args: Vec<_> = std::env::args_os().skip(1).collect();

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = std::process::Command::new(&exe).args(&args).exec();
        eprintln!("restart failed: {err}");
        std::process::exit(1);
    }

    #[cfg(windows)]
    {
        std::process::Command::new(&exe)
            .args(&args)
            .spawn()
            .expect("failed to spawn restart process");
        std::process::exit(0);
    }

    #[cfg(not(any(unix, windows)))]
    {
        eprintln!("restart is not supported on this platform");
        std::process::exit(1);
    }
}

async fn send_restart(api_addr: &str) -> Result<()> {
    use http_body_util::Empty;
    use hyper::Method;
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpStream;

    let req = hyper::Request::builder()
        .method(Method::POST)
        .uri(format!("http://{}/restart", api_addr))
        .body(Empty::<hyper::body::Bytes>::new())?;

    let stream = TcpStream::connect(api_addr).await?;
    let stream = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(stream).await?;
    tokio::spawn(conn);

    let resp = sender.send_request(req).await?;
    if resp.status() != 200 {
        return Err(anyhow!(
            "restart request failed with status: {}",
            resp.status()
        ));
    }

    info!("Restart signal sent successfully");
    Ok(())
}

fn load_config<T: de::DeserializeOwned>(path: &Path) -> Result<T> {
    let file = std::fs::File::open(path).with_context(|| {
        format!(
            "Failed to open configuration file: '{}'. Ensure the path is correct and the file is accessible.",
            path.display()
        )
    })?;

    serde_json::from_reader(file).context(format!(
        "Failed to parse configuration file '{}'. Check for syntax errors or invalid values.",
        path.display()
    ))
}

#[cfg(target_os = "android")]
pub(crate) fn logger_init() -> Result<()> {
    android_logger::init_once(
        android_logger::Config::default().with_max_level(LevelFilter::from_str(
            std::env::var("FUBUKI_LOG").as_deref().unwrap_or("INFO"),
        )?),
    );

    Ok(())
}

#[cfg(not(target_os = "android"))]
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
            .build(
                Root::builder()
                    .appender("stdout")
                    .build(log_level),
            )?;

        log4rs::init_config(config)?;
        Ok(())
    }

    static LOGGER_INIT: std::sync::Once = std::sync::Once::new();

    LOGGER_INIT.call_once(|| {
        init().expect("Critical error: Logger initialization failed. Please check log configuration.");
    });
    Ok(())
}

pub fn launch(args: Args) -> Result<()> {
    logger_init()?;

    match args {
        Args::Server { cmd } => {
            match cmd {
                ServerCmd::Daemon { config_path } => {
                    let t: ServerConfig = load_config(&config_path)?;
                    let config: ServerConfigFinalize<Key> = ServerConfigFinalize::try_from(t)?;
                    let rt = Runtime::new()?;
                    rt.block_on(server::start(config))?;
                    let should_restart = SHOULD_RESTART.load(Ordering::SeqCst);
                    drop(rt);
                    if should_restart {
                        info!("Restarting server process");
                        restart();
                    }
                }
                ServerCmd::Info { api } => {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?;

                    rt.block_on(server::info(&api))?;
                }
                ServerCmd::Restart { api } => {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?;

                    rt.block_on(send_restart(&api))?;
                }
            }
        }
        Args::Node { cmd } => {
            match cmd {
                #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
                NodeCmd::Daemon { config_path } => {
                    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
                    common::privilege::require_elevated_for_node()?;

                    let config: NodeConfig = load_config(&config_path)?;
                    let c: NodeConfigFinalize<Key> = NodeConfigFinalize::try_from(config)?;
                    let rt = Runtime::new()?;

                    rt.block_on(async {
                        let tun = tun::create().context("Failed to create TUN device. Ensure necessary drivers are installed and permissions are granted.")?;
                        node::start(c, tun, Arc::new(OnceLock::new())).await
                    })?;
                    let should_restart = SHOULD_RESTART.load(Ordering::SeqCst);
                    drop(rt);
                    if should_restart {
                        info!("Restarting node process");
                        restart();
                    }
                }
                NodeCmd::Info { api } => {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?;

                    rt.block_on(node::info(&api))?;
                }
                NodeCmd::Restart { api } => {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?;

                    rt.block_on(send_restart(&api))?;
                }
                #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
                _ => {
                    return Err(anyhow!(
                        "Fubuki is not supported on the current platform. This build only supports Windows, Linux, and macOS."
                    ));
                }
            }
        }
        Args::Update { repo_owner, repo_name } => {
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
