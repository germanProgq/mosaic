use anyhow::{Context, Result, bail, ensure};
use mosaic_core::{
    config::ClientConfig,
    proxy, quic,
    report::{Report, Status},
    session,
};
use std::{
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    path::Path,
    process::ExitCode,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Mutex,
    time::timeout,
};

const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(10);

pub struct Relay {
    config: ClientConfig,
    interface: Option<String>,
    current: Mutex<Option<quic::ClientConnection>>,
}

#[cfg(target_os = "macos")]
fn bind_interface(socket: &UdpSocket, name: &str) -> Result<()> {
    use std::os::fd::AsRawFd;
    let name = std::ffi::CString::new(name)?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    ensure!(index != 0, "network interface not found");
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_BOUND_IF,
            (&index as *const u32).cast(),
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    ensure!(result == 0, "cannot bind the relay socket to the interface");
    Ok(())
}

#[cfg(target_os = "linux")]
fn bind_interface(socket: &UdpSocket, name: &str) -> Result<()> {
    use std::os::fd::AsRawFd;
    let device = std::ffi::CString::new(name)?;
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            device.as_ptr().cast(),
            device.as_bytes_with_nul().len() as libc::socklen_t,
        )
    };
    ensure!(result == 0, "cannot bind the relay socket to the interface");
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn bind_interface(_: &UdpSocket, _: &str) -> Result<()> {
    bail!("interface binding is supported on macOS and Linux")
}

impl Relay {
    pub fn new(config: ClientConfig, interface: Option<String>) -> Self {
        Self {
            config,
            interface,
            current: Mutex::new(None),
        }
    }

    async fn connect(&self) -> Result<quic::ClientConnection> {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        if let Some(name) = &self.interface {
            bind_interface(&socket, name)?;
        }
        let client = quic::connect_socket(&self.config, socket).await?;
        session::authorize_proxy(&client.connection, &self.config).await?;
        Ok(client)
    }

    pub async fn connection(&self) -> Result<quinn::Connection> {
        let mut current = self.current.lock().await;
        if let Some(client) = current.as_ref()
            && client.connection.close_reason().is_none()
        {
            return Ok(client.connection.clone());
        }
        *current = None;
        let client = self.connect().await?;
        let connection = client.connection.clone();
        *current = Some(client);
        Ok(connection)
    }

    async fn open(
        &self,
        host: &str,
        port: u16,
    ) -> Result<Option<(quinn::SendStream, quinn::RecvStream)>> {
        for attempt in 0..2 {
            let connection = self.connection().await?;
            match proxy::open_stream(
                &connection,
                host,
                port,
                self.config.limits.max_control_bytes,
            )
            .await
            {
                Ok(result) => return Ok(result),
                Err(_) if attempt == 0 && connection.close_reason().is_some() => continue,
                Err(error) => return Err(error),
            }
        }
        bail!("relay connection unavailable")
    }
}

pub enum Target {
    Domain(String),
    Ipv4(Ipv4Addr),
}

pub async fn greeting<S: AsyncReadExt + AsyncWriteExt + Unpin>(client: &mut S) -> Result<()> {
    let mut header = [0u8; 2];
    client.read_exact(&mut header).await?;
    ensure!(header[0] == 5 && header[1] > 0, "unsupported SOCKS version");
    let mut methods = vec![0u8; usize::from(header[1])];
    client.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        client.write_all(&[5, 0xff]).await?;
        bail!("client requires SOCKS authentication");
    }
    client.write_all(&[5, 0]).await?;
    Ok(())
}

pub async fn request<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    client: &mut S,
) -> Result<Option<(Target, u16)>> {
    let mut header = [0u8; 4];
    client.read_exact(&mut header).await?;
    ensure!(header[0] == 5, "unsupported SOCKS version");
    let target = match header[3] {
        1 => {
            let mut address = [0u8; 4];
            client.read_exact(&mut address).await?;
            Target::Ipv4(Ipv4Addr::from(address))
        }
        3 => {
            let length = client.read_u8().await?;
            let mut name = vec![0u8; usize::from(length)];
            client.read_exact(&mut name).await?;
            Target::Domain(String::from_utf8(name).context("invalid destination name")?)
        }
        4 => {
            let mut skipped = [0u8; 18];
            client.read_exact(&mut skipped).await?;
            reply(client, 8).await?;
            return Ok(None);
        }
        _ => {
            reply(client, 8).await?;
            return Ok(None);
        }
    };
    let port = client.read_u16().await?;
    if header[1] != 1 {
        reply(client, 7).await?;
        return Ok(None);
    }
    Ok(Some((target, port)))
}

pub async fn reply<S: AsyncWriteExt + Unpin>(client: &mut S, code: u8) -> Result<()> {
    client.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    Ok(())
}

async fn handle(relay: Arc<Relay>, mut client: TcpStream) -> Result<()> {
    client.set_nodelay(true)?;
    let requested = timeout(HANDSHAKE_DEADLINE, async {
        greeting(&mut client).await?;
        request(&mut client).await
    })
    .await
    .context("SOCKS handshake deadline")??;
    let Some((target, port)) = requested else {
        return Ok(());
    };
    let host = match target {
        Target::Domain(name) => name,
        Target::Ipv4(ip) => ip.to_string(),
    };
    let streams = match relay.open(&host, port).await {
        Ok(Some(streams)) => streams,
        Ok(None) => {
            reply(&mut client, 5).await?;
            return Ok(());
        }
        Err(error) => {
            reply(&mut client, 1).await?;
            return Err(error);
        }
    };
    reply(&mut client, 0).await?;
    let (send, recv) = streams;
    splice(client, send, recv).await
}

async fn splice(
    client: TcpStream,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> Result<()> {
    let (mut read, mut write) = client.into_split();
    let upload = async {
        tokio::io::copy(&mut read, &mut send).await?;
        send.finish()?;
        Ok::<(), anyhow::Error>(())
    };
    let download = async {
        tokio::io::copy(&mut recv, &mut write).await?;
        write.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    };
    tokio::try_join!(upload, download)?;
    Ok(())
}

async fn shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let Ok(mut term) = signal(SignalKind::terminate()) else {
            return;
        };
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

async fn serve(config: &Path, listen: SocketAddr, interface: Option<String>) -> Result<()> {
    ensure!(
        listen.ip().is_loopback(),
        "the proxy listens only on a loopback address"
    );
    let config = ClientConfig::load(config)?;
    config.check_credentials()?;
    let listener = TcpListener::bind(listen)
        .await
        .context("cannot listen on the proxy address")?;
    let relay = Arc::new(Relay::new(config, interface));
    relay
        .connection()
        .await
        .context("cannot reach the relay; check the network path and credentials")?;
    let mut report = Report::new("local-proxy");
    report.add(
        "proxy.listen",
        Status::Pass,
        &format!("SOCKS5 proxy ready on {listen}; TCP through the relay; stop with Ctrl-C"),
    );
    report.emit(None)?;
    let accept = async {
        loop {
            let (client, _) = listener.accept().await?;
            let relay = relay.clone();
            tokio::spawn(async move {
                let _ = handle(relay, client).await;
            });
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    tokio::select! {
        result = accept => result,
        _ = shutdown() => Ok(()),
    }
}

pub async fn run(config: &Path, listen: SocketAddr, interface: Option<String>) -> ExitCode {
    match serve(config, listen, interface).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let mut report = Report::new("local-proxy");
            report.add("proxy.listen", Status::Fail, &format!("{error:#}"));
            let _ = report.emit(None);
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn parse(bytes: &[u8]) -> (Result<Option<(Target, u16)>>, Vec<u8>) {
        let (mut near, mut far) = tokio::io::duplex(1024);
        far.write_all(bytes).await.unwrap();
        let result = async {
            greeting(&mut near).await?;
            request(&mut near).await
        }
        .await;
        drop(near);
        let mut written = Vec::new();
        far.read_to_end(&mut written).await.unwrap();
        (result, written)
    }

    #[tokio::test]
    async fn socks_connect_requests_are_parsed() {
        let (result, written) = parse(&[
            5, 1, 0, 5, 1, 0, 3, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o',
            b'm', 1, 187,
        ])
        .await;
        let (target, port) = result.unwrap().unwrap();
        assert!(matches!(target, Target::Domain(name) if name == "example.com"));
        assert_eq!(port, 443);
        assert_eq!(written, [5, 0]);
        let (result, _) = parse(&[5, 1, 0, 5, 1, 0, 1, 1, 1, 1, 1, 0, 80]).await;
        let (target, port) = result.unwrap().unwrap();
        assert!(matches!(target, Target::Ipv4(ip) if ip == Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(port, 80);
    }

    #[tokio::test]
    async fn unsupported_socks_requests_are_refused() {
        let (result, written) = parse(&[5, 1, 2]).await;
        assert!(result.is_err());
        assert_eq!(written, [5, 0xff]);
        let (result, written) = parse(&[5, 1, 0, 5, 2, 0, 1, 1, 1, 1, 1, 0, 80]).await;
        assert!(result.unwrap().is_none());
        assert_eq!(&written[2..4], [5, 7]);
        let mut ipv6 = vec![5, 1, 0, 5, 1, 0, 4];
        ipv6.extend([0u8; 18]);
        let (result, written) = parse(&ipv6).await;
        assert!(result.unwrap().is_none());
        assert_eq!(&written[2..4], [5, 8]);
    }
}
