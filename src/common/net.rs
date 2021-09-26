use std::error::Error;
use std::io;
use std::net::{IpAddr, SocketAddr};

use socket2::{Socket, TcpKeepalive};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
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

const TCP_KEEPALIVE: TcpKeepalive = TcpKeepalive::new().with_time(Duration::from_secs(120));

#[cfg(target_os = "windows")]
fn set_keepalive<S: std::os::windows::io::AsRawSocket>(socket: &S) -> std::io::Result<()> {
    use std::os::windows::io::FromRawSocket;

    unsafe {
        let socket = Socket::from_raw_socket(socket.as_raw_socket());
        socket.set_tcp_keepalive(&TCP_KEEPALIVE)?;
        std::mem::forget(socket);
    };
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_keepalive<S: std::os::unix::io::AsRawFd>(socket: &S) -> std::io::Result<()> {
    use std::os::unix::io::FromRawFd;

    unsafe {
        let socket = Socket::from_raw_fd(socket.as_raw_fd());
        socket.set_tcp_keepalive(&TCP_KEEPALIVE)?;
        std::mem::forget(socket);
    };
    Ok(())
}

pub async fn get_interface_addr(dest_addr: SocketAddr) -> Result<IpAddr, Box<dyn Error>> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(dest_addr).await?;
    let addr = socket.local_addr()?;
    Ok(addr.ip())
}

pub mod msg {
    use std::error::Error;
    use std::net::SocketAddr;

    use crypto::rc4::Rc4;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::UdpSocket;

    use crate::common::proto;
    use crate::common::proto::{TcpMsg, UdpMsg};

    pub struct TcpMsgReader<'a, Rx: AsyncRead + Unpin> {
        rx: &'a mut Rx,
        rc4: &'a mut Rc4,
        buff: Box<[u8]>,
        out: Box<[u8]>,
    }

    impl<'a, Rx: AsyncRead + Unpin> TcpMsgReader<'a, Rx> {
        pub fn new(rx: &'a mut Rx, rc4: &'a mut Rc4) -> Self {
            let buff = vec![0u8; 65535].into_boxed_slice();
            let out = vec![0u8; 65535].into_boxed_slice();
            TcpMsgReader { rx, rc4, buff, out }
        }

        pub async fn read(&mut self) -> Result<TcpMsg<'_>, Box<dyn Error>> {
            let buff = &mut self.buff;
            let out = &mut self.out;

            let len = self.rx.read_u16().await?;
            let data = &mut buff[..len as usize];
            self.rx.read_exact(data).await?;

            let out = proto::crypto(data, out, self.rc4)?;
            Ok(TcpMsg::decode(out)?)
        }
    }

    pub struct TcpMsgWriter<'a, Tx: AsyncWrite + Unpin> {
        tx: &'a mut Tx,
        rc4: &'a mut Rc4,
        buff: Box<[u8]>,
        out: Box<[u8]>,
    }

    impl<'a, Tx: AsyncWrite + Unpin> TcpMsgWriter<'a, Tx> {
        pub fn new(tx: &'a mut Tx, rc4: &'a mut Rc4) -> Self {
            let buff = vec![0u8; 65535].into_boxed_slice();
            let out = vec![0u8; 65535].into_boxed_slice();
            TcpMsgWriter { tx, rc4, buff, out }
        }

        pub async fn read(&mut self, msg: &TcpMsg<'_>) -> Result<(), Box<dyn Error>> {
            let buff = &mut self.buff;
            let out = &mut self.out;

            let data = msg.encode(buff)?;
            let out = proto::crypto(data, out, self.rc4)?;

            let len = out.len();
            buff[..2].copy_from_slice(&(len as u16).to_be_bytes());
            buff[2..len + 2].copy_from_slice(out);

            self.tx.write_all(&buff[..len + 2]).await?;
            Ok(())
        }
    }

    pub struct UdpMsgSocket<'a> {
        socket: &'a UdpSocket,
        rc4: Rc4,
        buff: [u8; 2048],
        out: [u8; 2048],
    }

    impl<'a> UdpMsgSocket<'a> {
        pub fn new(socket: &'a UdpSocket, rc4: Rc4) -> Self {
            UdpMsgSocket { socket, rc4, buff: [0u8; 2048], out: [0u8; 2048] }
        }

        pub async fn read(&mut self) -> Result<(UdpMsg<'_>, SocketAddr), Box<dyn Error>> {
            let socket = self.socket;
            let mut rc4 = self.rc4;
            let buff = &mut self.buff;
            let out = &mut self.out;

            let (len, peer_addr) = socket.recv_from(buff).await?;
            let data = &buff[..len];
            let packet = proto::crypto(data, out, &mut rc4)?;

            Ok((UdpMsg::decode(packet)?, peer_addr))
        }

        pub async fn write(&mut self, msg: &UdpMsg<'_>, dest_addr: SocketAddr) -> Result<(), Box<dyn Error>> {
            let socket = self.socket;
            let mut rc4 = self.rc4;
            let buff = &mut self.buff;
            let out = &mut self.out;

            let data = msg.encode(buff)?;
            let packet = proto::crypto(data, out, &mut rc4)?;
            socket.send_to(packet, dest_addr).await?;
            Ok(())
        }
    }
}