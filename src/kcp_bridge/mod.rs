use crate::common::allocator::Bytes;
use crate::common::cipher::Cipher;
use crate::common::net::protocol::{UdpMsg, UdpSocketErr, TCP_BUFF_SIZE, UDP_BUFF_SIZE, UDP_MSG_HEADER_LEN};
use anyhow::anyhow;
use chrono::Utc;
use kcp::Kcp;
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};
use stackfuture::StackFuture;
use std::cell::LazyCell;
use std::future::Future;
use std::task::Poll;
use std::time::Duration;
use std::{io, net::SocketAddr, pin::Pin, task::ready};
use tokio::io::AsyncRead;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::{io::AsyncWrite, net::UdpSocket};

const READY_FUTURE_SIZE: usize = 256;

struct KcpOutput<'a, K> {
    socket: &'a UdpSocket,
    to: SocketAddr,
    ready_fut: Box<Option<StackFuture<'a, io::Result<()>, READY_FUTURE_SIZE>>>,
    udp_buff: Vec<u8>,
    key: &'a K,
    rng: SmallRng
}

impl <K: Cipher> AsyncWrite for KcpOutput<'_, K> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, io::Error>> {
        let this = self.get_mut();
        let buff = &mut *this.udp_buff;
        let rng = &mut this.rng;
        let key = this.key;
        let socket = this.socket;
        let to = this.to;
        let packet = LazyCell::new(|| {
            let sub_buff = &mut buff[UDP_MSG_HEADER_LEN..];
            sub_buff[..buf.len()].copy_from_slice(buf);

            let len = UdpMsg::kcp_data_encode(
                key,
                rng.random(),
                buf.len(),
                buff
            );

            let packet = &buff[..len];
            packet
        });

        loop {
            let ready_fut = this.ready_fut.as_mut();

            if ready_fut.is_none() {
                let fut = this.socket.writable();
                let fut = StackFuture::from(fut);
                ready_fut.replace(fut);
            }

            let fut = ready_fut.as_mut().unwrap();
            let fut = unsafe { Pin::new_unchecked(fut) };
            ready!(fut.poll(cx))?;
            *ready_fut = None;

            match UdpMsg::try_send_msg(socket, *packet, to) {
                Ok(_) => return Poll::Ready(Ok(buf.len())),
                Err(UdpSocketErr::SuppressError(e)) => {
                    warn!("error sending kcp packet: {}", e);
                    return Poll::Ready(Ok(buf.len()))
                }
                Err(UdpSocketErr::FatalError(ref e)) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(UdpSocketErr::FatalError(e)) => return Poll::Ready(Err(e)),
            }
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }
}

pub struct KcpStack<'a, Tx, Rx, K> {
    kcp: Kcp<KcpOutput<'a, K>>,
    tx: &'a mut Tx,
    rx: &'a mut Rx,
    stack_rx: &'a mut mpsc::Receiver<Bytes>,
}

impl<'a, Tx, Rx, K> KcpStack<'a, Tx, Rx, K>
where
    Tx: AsyncWrite + Unpin,
    Rx: AsyncRead + Unpin,
    K: Cipher
{
    pub fn new(
        socket: &'a UdpSocket, 
        to: SocketAddr, 
        conv: u32,
        tx: &'a mut Tx,
        rx: &'a mut Rx,
        stack_rx: &'a mut mpsc::Receiver<Bytes>,
        key: &'a K
    ) -> Self {
        let output = KcpOutput {
            socket,
            to,
            ready_fut: Box::new(None),
            udp_buff: vec![0u8; UDP_BUFF_SIZE],
            key,
            rng: rand::rngs::SmallRng::from_os_rng()
        };

        let kcp = kcp::Kcp::new_stream(conv, output);

        KcpStack {
            kcp,
            tx,
            rx,
            stack_rx,
        }
    }

    pub async fn block_on(&mut self) -> anyhow::Result<()> {
        let mut buff = vec![0u8; TCP_BUFF_SIZE];

        macro_rules! update_and_recv {
            () => {{
                let now = Utc::now().timestamp_millis() as u32;
                self.kcp.async_update(now).await?;

                match self.kcp.recv(&mut buff) {
                    Ok(len) => {
                        let packet = &buff[..len];
                        self.tx.write_all(&packet).await?;
                    }
                    Err(kcp::Error::RecvQueueEmpty) => (),
                    Err(e) => return Err(anyhow!("failed to recv kcp packet {}", e))
                }
            }};
        }

        loop {
            let now = Utc::now().timestamp_millis() as u32;
            let sleep = self.kcp.check(now);

            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(sleep as u64)) => {
                    update_and_recv!();
                }
                opt = self.stack_rx.recv() => {
                    match opt {
                        Some(bytes) => {
                            match self.kcp.input(&bytes) {
                                Ok(_) => update_and_recv!(),
                                Err(e) => warn!("failed to kcp input: {}", e)
                            }
                        }
                        None => return Ok(())
                    };
                }
                res = self.rx.read(&mut buff) => {
                    let len = res?;

                    if len == 0 {
                        return Ok(());
                    }

                    let packet = &buff[..len];
                    self.kcp.send(packet)?;
                    update_and_recv!();
                }
            }
        }
    }
}
