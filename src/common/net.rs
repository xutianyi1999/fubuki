use socket2::Socket;
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::Duration;

pub trait TcpSocketExt {
    fn set_keepalive(&self) -> tokio::io::Result<()>;
}

impl TcpSocketExt for TcpStream {
    fn set_keepalive(&self) -> tokio::io::Result<()> {
        set_keepalive(self)
    }
}

impl TcpSocketExt for TcpSocket {
    fn set_keepalive(&self) -> tokio::io::Result<()> {
        set_keepalive(self)
    }
}

const KEEPALIVE_DURATION: Option<Duration> = Option::Some(Duration::from_secs(120));

#[cfg(target_os = "windows")]
pub fn set_keepalive<S: std::os::windows::io::AsRawSocket>(socket: &S) -> tokio::io::Result<()> {
    use std::os::windows::io::FromRawSocket;

    unsafe {
        let socket = Socket::from_raw_socket(socket.as_raw_socket());
        socket.set_keepalive(KEEPALIVE_DURATION)?;
        std::mem::forget(socket);
    };
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn set_keepalive<S: std::os::unix::io::AsRawFd>(socket: &S) -> tokio::io::Result<()> {
    use std::os::unix::io::FromRawFd;

    unsafe {
        let socket = Socket::from_raw_fd(socket.as_raw_fd());
        socket.set_keepalive(KEEPALIVE_DURATION)?;
        std::mem::forget(socket);
    };
    Ok(())
}