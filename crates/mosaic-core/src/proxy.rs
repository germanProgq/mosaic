use crate::{
    frame,
    tcp_connect::{Request, Response, checked_addresses},
};
use anyhow::{Context, Result, bail, ensure};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{io::AsyncWriteExt, net::TcpStream, task::JoinSet, time::timeout};

pub const MAX_STREAMS: u32 = 256;
pub const BLOCKED_PORTS: [u16; 1] = [25];
const CONNECT_DEADLINE: Duration = Duration::from_secs(10);

pub fn destination(host: &str, port: u16) -> Result<()> {
    ensure!(
        port != 0 && !BLOCKED_PORTS.contains(&port),
        "destination port not allowed"
    );
    ensure!(
        !host.is_empty()
            && host.len() <= 253
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')),
        "invalid destination host"
    );
    Ok(())
}

pub fn excluded(address: &SocketAddr, networks: &[(u32, u32)]) -> bool {
    match address.ip() {
        IpAddr::V4(ip) => {
            let ip = u32::from(ip);
            networks
                .iter()
                .any(|(network, mask)| ip & mask == network & mask)
        }
        IpAddr::V6(_) => true,
    }
}

#[cfg(unix)]
pub fn local_networks() -> Vec<(u32, u32)> {
    let mut networks = Vec::new();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return networks;
    }
    let mut current = head;
    while !current.is_null() {
        let entry = unsafe { &*current };
        if !entry.ifa_addr.is_null()
            && !entry.ifa_netmask.is_null()
            && i32::from(unsafe { (*entry.ifa_addr).sa_family }) == libc::AF_INET
        {
            let address = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in) };
            let mask = unsafe { &*(entry.ifa_netmask as *const libc::sockaddr_in) };
            networks.push((
                u32::from_be(address.sin_addr.s_addr),
                u32::from_be(mask.sin_addr.s_addr),
            ));
        }
        current = entry.ifa_next;
    }
    unsafe { libc::freeifaddrs(head) };
    networks
}

#[cfg(not(unix))]
pub fn local_networks() -> Vec<(u32, u32)> {
    Vec::new()
}

async fn open(host: &str, port: u16, local: &[(u32, u32)]) -> Result<TcpStream> {
    destination(host, port)?;
    timeout(CONNECT_DEADLINE, async {
        let addresses = match host.parse::<Ipv4Addr>() {
            Ok(ip) => checked_addresses(std::iter::once(SocketAddr::from((ip, port))))?,
            Err(_) => checked_addresses(tokio::net::lookup_host((host, port)).await?)?,
        };
        for address in addresses {
            if excluded(&address, local) {
                continue;
            }
            if let Ok(stream) = TcpStream::connect(address).await {
                stream.set_nodelay(true)?;
                return Ok(stream);
            }
        }
        bail!("destination TCP unavailable")
    })
    .await
    .context("destination resolution or connection deadline")?
}

pub async fn splice(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    tcp: TcpStream,
) -> Result<()> {
    let (mut read, mut write) = tcp.into_split();
    let upload = async {
        tokio::io::copy(&mut recv, &mut write).await?;
        write.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    };
    let download = async {
        tokio::io::copy(&mut read, &mut send).await?;
        send.finish()?;
        Ok::<(), anyhow::Error>(())
    };
    let result = tokio::try_join!(upload, download).map(|_| ());
    if result.is_err() {
        let _ = send.reset(1u32.into());
        let _ = recv.stop(1u32.into());
    }
    result
}

async fn stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    control_limit: usize,
    local: Arc<Vec<(u32, u32)>>,
) {
    let opened = async {
        let Request::OpenTcp { host, port } = timeout(
            Duration::from_secs(5),
            frame::read_control(&mut recv, control_limit),
        )
        .await??;
        Ok::<_, anyhow::Error>(open(&host, port, &local).await)
    }
    .await;
    let tcp = match opened {
        Ok(Ok(tcp)) => tcp,
        Ok(Err(_)) => {
            if frame::write_control(&mut send, &Response::TcpRejected, control_limit)
                .await
                .is_ok()
            {
                let _ = send.finish();
            }
            let _ = recv.stop(1u32.into());
            return;
        }
        Err(_) => {
            let _ = send.reset(1u32.into());
            let _ = recv.stop(1u32.into());
            return;
        }
    };
    if frame::write_control(&mut send, &Response::ProxyReady, control_limit)
        .await
        .is_err()
    {
        return;
    }
    let _ = splice(send, recv, tcp).await;
}

pub async fn serve(connection: &quinn::Connection, control_limit: usize, public: &[Ipv4Addr]) {
    connection.set_max_concurrent_bi_streams(MAX_STREAMS.into());
    let mut networks = local_networks();
    networks.extend(public.iter().map(|ip| (u32::from(*ip), u32::MAX)));
    let local = Arc::new(networks);
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            _ = connection.read_datagram() => break,
            _ = tasks.join_next(), if !tasks.is_empty() => {}
            incoming = connection.accept_bi() => {
                let Ok((send, recv)) = incoming else { break; };
                tasks.spawn(stream(send, recv, control_limit, local.clone()));
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    connection.close(0u32.into(), b"proxy ended");
}

pub async fn open_stream(
    connection: &quinn::Connection,
    host: &str,
    port: u16,
    control_limit: usize,
) -> Result<Option<(quinn::SendStream, quinn::RecvStream)>> {
    destination(host, port)?;
    let (mut send, mut recv) = connection.open_bi().await?;
    frame::write_control(
        &mut send,
        &Request::OpenTcp {
            host: host.into(),
            port,
        },
        control_limit,
    )
    .await?;
    let response: Response = timeout(
        CONNECT_DEADLINE + Duration::from_secs(5),
        frame::read_control(&mut recv, control_limit),
    )
    .await
    .context("relay did not answer the connection request")??;
    match response {
        Response::ProxyReady => Ok(Some((send, recv))),
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destinations_are_validated() {
        assert!(destination("example.com", 443).is_ok());
        assert!(destination("93.184.215.14", 80).is_ok());
        assert!(destination("example.com", 25).is_err());
        assert!(destination("example.com", 0).is_err());
        assert!(destination("", 443).is_err());
        assert!(destination("bad host", 443).is_err());
        assert!(destination(&"a".repeat(254), 443).is_err());
    }

    #[test]
    fn local_networks_are_excluded() {
        let networks = [(u32::from(Ipv4Addr::new(203, 0, 113, 76)), 0xffff_ff00)];
        assert!(excluded(&"203.0.113.76:22".parse().unwrap(), &networks));
        assert!(excluded(&"203.0.113.9:443".parse().unwrap(), &networks));
        assert!(!excluded(&"198.51.100.119:443".parse().unwrap(), &networks));
        assert!(excluded(&"[2001:db8::1]:443".parse().unwrap(), &networks));
    }
}
