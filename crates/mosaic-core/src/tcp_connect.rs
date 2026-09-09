use crate::{config::Fetch, frame};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
    time::{Instant, timeout},
};

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum Request {
    OpenTcp { host: String, port: u16 },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum Response {
    TcpReady { max_bytes: u64, timeout_s: u64 },
    TcpRejected,
}

pub fn public_ipv4(ip: Ipv4Addr) -> bool {
    if ip == Ipv4Addr::new(168, 63, 129, 16) {
        return false;
    }
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || a >= 224
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && (b == 168 || (b == 0 && (c == 0 || c == 2)) || (b == 88 && c == 99)))
        || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
        || (a == 203 && b == 0 && c == 113))
}

pub fn allowed(settings: &Fetch, host: &str, port: u16) -> Result<()> {
    ensure!(
        host.len() <= 253
            && settings
                .allow
                .iter()
                .any(|d| d.host.eq_ignore_ascii_case(host) && d.port == port),
        "destination not allowed"
    );
    Ok(())
}

pub fn checked_addresses(addresses: impl Iterator<Item = SocketAddr>) -> Result<Vec<SocketAddr>> {
    let mut checked = Vec::new();
    for (index, address) in addresses.enumerate() {
        ensure!(index < 32, "too many destination addresses");
        match address.ip() {
            IpAddr::V4(ip) => {
                ensure!(public_ipv4(ip), "destination address not public");
                if !checked.contains(&address) {
                    checked.push(address);
                }
            }
            IpAddr::V6(_) => continue,
        }
    }
    ensure!(
        !checked.is_empty(),
        "destination has no public IPv4 address"
    );
    Ok(checked)
}

async fn connect(settings: &Fetch, host: &str, port: u16) -> Result<TcpStream> {
    allowed(settings, host, port)?;
    timeout(Duration::from_secs(5), async {
        let addresses = checked_addresses(tokio::net::lookup_host((host, port)).await?)?;
        for address in addresses {
            if let Ok(stream) = TcpStream::connect(address).await {
                return Ok(stream);
            }
        }
        bail!("destination TCP unavailable")
    })
    .await
    .context("destination resolution or connection deadline")?
}

pub struct Pacer(Mutex<Instant>);

impl Default for Pacer {
    fn default() -> Self {
        Self(Mutex::new(Instant::now()))
    }
}

impl Pacer {
    async fn wait(&self, bytes: usize) {
        let at = {
            let mut next = self.0.lock().await;
            let at = (*next).max(Instant::now());
            *next = at + Duration::from_secs_f64((bytes + 128) as f64 / 80_000.0);
            at
        };
        tokio::time::sleep_until(at).await;
    }
}

async fn copy<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    remaining: &AtomicU64,
    pacer: &Pacer,
) -> Result<()> {
    let mut buffer = [0; 4096];
    loop {
        let size = reader.read(&mut buffer).await?;
        if size == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        ensure!(
            remaining
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |left| left
                    .checked_sub(size as u64))
                .is_ok(),
            "TCP byte limit exceeded"
        );
        pacer.wait(size).await;
        writer.write_all(&buffer[..size]).await?;
    }
}

pub async fn forward(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    tcp: TcpStream,
    remaining: &AtomicU64,
    pacer: &Pacer,
) -> Result<()> {
    let (mut read, mut write) = tcp.into_split();
    tokio::try_join!(
        copy(recv, &mut write, remaining, pacer),
        copy(&mut read, send, remaining, pacer)
    )?;
    Ok(())
}

pub async fn serve(
    connection: &quinn::Connection,
    settings: &Fetch,
    control_limit: usize,
    pacer: Arc<Pacer>,
) {
    let remaining = AtomicU64::new(settings.max_bytes);
    let work = async {
        for _ in 0..settings.max_requests {
            let (mut send, mut recv) = connection.accept_bi().await?;
            let result = async {
                let Request::OpenTcp { host, port } = timeout(
                    Duration::from_secs(5),
                    frame::read_control(&mut recv, control_limit),
                )
                .await??;
                let tcp = match connect(settings, &host, port).await {
                    Ok(tcp) => tcp,
                    Err(_) => {
                        frame::write_control(&mut send, &Response::TcpRejected, control_limit)
                            .await?;
                        send.finish()?;
                        let _ = recv.stop(1u32.into());
                        send.stopped().await?;
                        return Ok(());
                    }
                };
                frame::write_control(
                    &mut send,
                    &Response::TcpReady {
                        max_bytes: remaining.load(Ordering::Relaxed),
                        timeout_s: settings.timeout_s,
                    },
                    control_limit,
                )
                .await?;
                forward(&mut send, &mut recv, tcp, &remaining, &pacer).await?;
                send.stopped().await?;
                Ok::<(), anyhow::Error>(())
            }
            .await;
            if result.is_err() {
                let _ = send.reset(1u32.into());
                let _ = recv.stop(1u32.into());
                return result;
            }
        }
        Ok::<(), anyhow::Error>(())
    };
    let _ = timeout(Duration::from_secs(settings.timeout_s), async {
        tokio::select! {
            _ = connection.read_datagram() => bail!("datagrams unavailable in fetch mode"),
            result = work => result,
        }
    })
    .await;
    connection.close(0u32.into(), b"fetch ended");
}
