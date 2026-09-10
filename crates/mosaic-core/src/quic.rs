use crate::config::{ClientConfig, RelayConfig, Transport, certificates, read_bounded};
use crate::{frame, session};
use anyhow::{Context, Result, ensure};
use quinn::{
    Connection, Endpoint, TransportConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use std::{future::Future, io::BufReader, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    sync::{Mutex, mpsc},
    task::JoinSet,
    time::{Instant, timeout},
};

pub const CONNECT_DEADLINE: Duration = Duration::from_secs(5);
pub const STREAM_DEADLINE: Duration = Duration::from_secs(15);
pub const MAX_ECHO_BYTES: usize = 65536;
pub const ECHO_SIZES: [usize; 5] = [0, 1, 64, 1024, MAX_ECHO_BYTES];
pub const ECHO_COUNT: usize = 100;
pub const CONCURRENT_STREAMS: usize = 3;
const MAX_CONNECTIONS: usize = 8;
const MAX_TRACKED_CONNECTIONS: usize = 64;
const CONNECTION_LIFETIME: Duration = Duration::from_secs(240);

fn transport(c: &Transport, server: bool) -> Arc<TransportConfig> {
    let mut t = TransportConfig::default();
    t.max_idle_timeout(Some(
        Duration::from_secs(c.idle_timeout_s)
            .try_into()
            .expect("validated timeout"),
    ))
    .keep_alive_interval(Some(Duration::from_secs(c.keepalive_s)))
    .max_concurrent_bidi_streams(if server { 3u32 } else { 0u32 }.into())
    .max_concurrent_uni_streams(0u32.into())
    .stream_receive_window((MAX_ECHO_BYTES as u32 + 1).into())
    .receive_window((256u32 * 1024).into())
    .send_window(256 * 1024)
    .datagram_receive_buffer_size(Some(frame::DATAGRAM_BUFFER_BYTES))
    .datagram_send_buffer_size(frame::DATAGRAM_BUFFER_BYTES);
    Arc::new(t)
}

pub fn client_config(c: &ClientConfig) -> Result<quinn::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in certificates(&c.tls.trust_cert)? {
        roots.add(cert).context("invalid trust certificate")?;
    }
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![c.transport.alpn.as_bytes().to_vec()];
    tls.enable_early_data = false;
    tls.resumption = rustls::client::Resumption::disabled();
    let mut config = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
    config.transport_config(transport(&c.transport, false));
    Ok(config)
}

pub fn relay_endpoint(c: &RelayConfig) -> Result<Endpoint> {
    let certs = certificates(&c.tls.cert)?;
    let bytes = read_bounded(&c.tls.key, 16384, true)?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(bytes.as_slice()))?
        .context("missing relay private key")?;
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    tls.alpn_protocols = vec![c.transport.alpn.as_bytes().to_vec()];
    tls.max_early_data_size = 0;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    config.transport_config(transport(&c.transport, true));
    config
        .max_incoming(MAX_CONNECTIONS)
        .incoming_buffer_size(65536)
        .incoming_buffer_size_total(512 * 1024);
    Endpoint::server(config, c.listen).context("cannot bind relay UDP socket")
}

/// Owns the outbound-only endpoint so success, failure and cancellation all release it.
pub struct ClientConnection {
    pub connection: Connection,
    endpoint: Endpoint,
}
impl Drop for ClientConnection {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"diagnostic finished");
    }
}

pub async fn connect(c: &ClientConfig) -> Result<ClientConnection> {
    let config = client_config(c)?;
    let bind: SocketAddr = if c.server.address.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }
    .parse()?;
    // No server config: this UDP socket cannot accept unsolicited QUIC connections.
    // Ordinary OS routing applies; no interface binding, bypass mark or proxy listener.
    let mut endpoint = Endpoint::client(bind).context("cannot create outbound UDP socket")?;
    endpoint.set_default_client_config(config);
    connect_endpoint(c, endpoint).await
}

pub async fn connect_socket(
    c: &ClientConfig,
    socket: std::net::UdpSocket,
) -> Result<ClientConnection> {
    socket.set_nonblocking(true)?;
    let mut endpoint = Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )?;
    endpoint.set_default_client_config(client_config(c)?);
    connect_endpoint(c, endpoint).await
}

async fn connect_endpoint(c: &ClientConfig, endpoint: Endpoint) -> Result<ClientConnection> {
    let attempt = endpoint.connect(c.server.address, &c.server.name)?;
    let connection = match timeout(CONNECT_DEADLINE, attempt).await {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            endpoint.close(0u32.into(), b"handshake failed");
            return Err(e.into());
        }
        Err(error) => {
            endpoint.close(0u32.into(), b"handshake deadline");
            return Err(anyhow::Error::new(error)
                .context("connection did not complete within five seconds"));
        }
    };
    Ok(ClientConnection {
        connection,
        endpoint,
    })
}

pub async fn connect_ready(c: &ClientConfig) -> Result<(ClientConnection, session::Ready)> {
    let client = connect(c).await?;
    let ready = session::authorize(&client.connection, c).await?;
    Ok((client, ready))
}

fn diagnostic_payload(sequence: usize, size: usize) -> Vec<u8> {
    (0..size)
        .map(|i| ((i * 31 + sequence * 17 + size) % 256) as u8)
        .collect()
}

pub struct DatagramOptions {
    pub count: usize,
    pub size: usize,
    pub rate: u32,
}

impl DatagramOptions {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=10000).contains(&self.count)
                && (1..=frame::MTU).contains(&self.size)
                && (1..=50).contains(&self.rate),
            "datagram count must be 1..10000, size 1..1100 and rate 1..50"
        );
        ensure!(
            self.count as f64 / self.rate as f64 <= 210.0,
            "datagram schedule exceeds time limit"
        );
        Ok(())
    }
}

pub async fn datagram_suite(
    connection: &Connection,
    options: &DatagramOptions,
    max_mbps: f64,
) -> Result<usize> {
    options.validate()?;
    ensure!(
        max_mbps.is_finite() && max_mbps > 0.0 && max_mbps <= 1.0,
        "invalid diagnostic rate limit"
    );
    session::send_limit(connection)?;
    let interval = Duration::from_secs_f64(
        (1.0 / options.rate as f64)
            .max((options.size + frame::PACKET_HEADER_BYTES + 96) as f64 / (max_mbps * 50_000.0)),
    );
    ensure!(
        interval.as_secs_f64() * options.count as f64 <= 210.0,
        "datagram schedule exceeds time limit"
    );
    timeout(CONNECTION_LIFETIME, async {
        let mut seen = vec![false; options.count];
        let mut sent = 0;
        let mut received = 0;
        let mut next = Instant::now();
        let mut finish = None;
        loop {
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(finish.unwrap_or(next)), if finish.is_some() => break,
                bytes = connection.read_datagram() => {
                    let bytes = bytes?;
                    let (sequence, payload) = frame::read_packet(&bytes)?;
                    ensure!(sequence < sent as u64, "unexpected datagram sequence");
                    let sequence = sequence as usize;
                    ensure!(payload == diagnostic_payload(sequence, options.size), "datagram byte mismatch");
                    if !seen[sequence] { seen[sequence] = true; received += 1; }
                }
                _ = tokio::time::sleep_until(next), if sent < options.count => {
                    session::send_limit(connection)?;
                    connection.send_datagram_wait(frame::packet(sent as u64, &diagnostic_payload(sent, options.size))?.into()).await?;
                    sent += 1;
                    next = Instant::now() + interval;
                    if sent == options.count { finish = Some(Instant::now() + Duration::from_secs(3)); }
                }
            }
        }
        let minimum = if connection.remote_address().ip().is_loopback() { options.count } else { (options.count * 99).div_ceil(100) };
        ensure!(received >= minimum, "datagram loss exceeds limit");
        Ok(received)
    }).await.context("datagram suite exceeded four minutes")?
}

// One shared schedule per sender, including all its simultaneous streams. Reserve small
// chunks with overhead headroom rather than releasing a full 192 KiB batch in a burst.
struct Pacer {
    next: Mutex<Instant>,
    bytes_per_second: f64,
}
impl Pacer {
    fn new(max_mbps: f64) -> Self {
        Self {
            next: Mutex::new(Instant::now()),
            bytes_per_second: max_mbps * 50_000.0,
        }
    }
    async fn wait(&self, bytes: usize) {
        let at = {
            let mut next = self.next.lock().await;
            let at = (*next).max(Instant::now());
            *next = at + Duration::from_secs_f64((bytes + 96) as f64 / self.bytes_per_second);
            at
        };
        tokio::time::sleep_until(at).await;
    }
}
async fn write_payload(
    send: &mut quinn::SendStream,
    bytes: &[u8],
    pacer: Option<&Pacer>,
) -> Result<()> {
    for chunk in bytes.chunks(1024) {
        if let Some(pacer) = pacer {
            pacer.wait(chunk.len()).await;
        }
        send.write_all(chunk).await?;
    }
    Ok(())
}

pub async fn echo(connection: &Connection, payload: &[u8]) -> Result<()> {
    echo_paced(connection, payload, None).await
}
async fn echo_paced(connection: &Connection, payload: &[u8], pacer: Option<&Pacer>) -> Result<()> {
    ensure!(
        payload.len() <= MAX_ECHO_BYTES,
        "echo payload exceeds limit"
    );
    timeout(STREAM_DEADLINE, async {
        let (mut send, mut recv) = connection.open_bi().await?;
        write_payload(&mut send, payload, pacer).await?;
        send.finish()?;
        let response = recv.read_to_end(MAX_ECHO_BYTES).await?;
        ensure!(response == payload, "echo byte mismatch");
        Ok(())
    })
    .await
    .context("echo exceeded fifteen seconds")?
}

/// 100 payloads per size, with up to three simultaneous streams on one QUIC connection.
/// Remote runs pace aggregate request+response payload to 0.8 Mbit/s (headroom for QUIC).
/// Loopback fixtures run without pacing; this is not a throughput benchmark.
pub async fn echo_suite(connection: &Connection, max_mbps: f64) -> Result<Vec<(usize, usize)>> {
    ensure!(
        max_mbps.is_finite() && max_mbps > 0.0 && max_mbps <= 1.0,
        "invalid diagnostic rate limit"
    );
    let pacer =
        (!connection.remote_address().ip().is_loopback()).then(|| Arc::new(Pacer::new(max_mbps)));
    timeout(CONNECTION_LIFETIME, async {
        let mut outcomes = Vec::new();
        for size in ECHO_SIZES {
            for first in (0..ECHO_COUNT).step_by(CONCURRENT_STREAMS) {
                let n = CONCURRENT_STREAMS.min(ECHO_COUNT - first);
                let mut jobs = JoinSet::new();
                for iteration in first..first + n {
                    let connection = connection.clone();
                    let payload: Vec<u8> = (0..size)
                        .map(|i| ((i * 31 + iteration * 17 + size) % 256) as u8)
                        .collect();
                    let pacer = pacer.clone();
                    jobs.spawn(
                        async move { echo_paced(&connection, &payload, pacer.as_deref()).await },
                    );
                }
                while let Some(result) = jobs.join_next().await {
                    result??;
                }
            }
            outcomes.push((size, ECHO_COUNT));
        }
        Ok(outcomes)
    })
    .await
    .context("echo suite exceeded four minutes")?
}

async fn serve_connection(
    connection: Connection,
    pacer: Option<Arc<Pacer>>,
    settings: Arc<session::Settings>,
    tunnel: Option<Arc<crate::config::Tunnel>>,
    fetch_pacer: Arc<crate::tcp_connect::Pacer>,
) {
    let Ok(ready) = session::accept(&connection, &settings).await else {
        return;
    };
    if ready.mode == "fetch" {
        if let Some(fetch) = &settings.fetch {
            crate::tcp_connect::serve(&connection, fetch, settings.control_limit, fetch_pacer)
                .await;
        }
        return;
    }
    if ready.mode == "tunnel" {
        #[cfg(target_os = "linux")]
        if let Some(config) = tunnel {
            match crate::tun::Tun::create(&config) {
                Ok(tun) => {
                    let counters = Arc::new(crate::pump::Counters::default());
                    let mut report = crate::report::Report::new("relay-tunnel-ready");
                    report.check_level = 3;
                    report.add(
                        "relay.tun",
                        crate::report::Status::Pass,
                        "exclusive TUN opened for the authenticated owner with MTU 1100",
                    );
                    if report.emit(None).is_ok() {
                        let _ = crate::pump::run(
                            &connection,
                            &tun,
                            crate::pump::Options {
                                outbound: crate::packet::Address::Destination(config.peer),
                                inbound: crate::packet::Address::Source(config.peer),
                                queue_packets: settings.queue_packets,
                                max_mbps: 1.0,
                            },
                            counters.clone(),
                        )
                        .await;
                    }
                    use std::sync::atomic::Ordering;
                    eprintln!(
                        "relay tunnel sent={} received={} rejected={} dropped={}",
                        counters.sent.load(Ordering::Relaxed),
                        counters.received.load(Ordering::Relaxed),
                        counters.rejected.load(Ordering::Relaxed),
                        counters.dropped.load(Ordering::Relaxed)
                    );
                }
                Err(_) => {
                    let mut report = crate::report::Report::new("relay-tunnel");
                    report.check_level = 3;
                    report.add("relay.tun", crate::report::Status::Fail, "exclusive TUN setup failed; inspect Linux privileges, subnet and interface inventory");
                    let _ = report.emit(None);
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = tunnel;
        connection.close(0u32.into(), b"tunnel ended");
        drop(ready);
        return;
    }
    let mut packets = JoinSet::new();
    let (tx, mut rx) = mpsc::channel(settings.queue_packets);
    let reader = connection.clone();
    packets.spawn(async move {
        loop {
            let bytes = match reader.read_datagram().await {
                Ok(bytes) => bytes,
                Err(error) => return Err::<(), anyhow::Error>(error.into()),
            };
            frame::read_packet(&bytes)?;
            match tx.try_send(bytes) {
                Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
                Err(mpsc::error::TrySendError::Closed(_)) => anyhow::bail!("packet sender stopped"),
            }
        }
    });
    let writer = connection.clone();
    let packet_pacer = pacer.clone();
    packets.spawn(async move {
        while let Some(bytes) = rx.recv().await {
            if let Some(pacer) = &packet_pacer {
                pacer.wait(bytes.len()).await;
            }
            session::send_limit(&writer)?;
            writer.send_datagram_wait(bytes).await?;
        }
        Ok::<(), anyhow::Error>(())
    });
    let mut streams = JoinSet::new();
    let work = async {
        let mut accepted = 0usize;
        loop {
            tokio::select! {
                _ = packets.join_next() => break,
                result = streams.join_next(), if !streams.is_empty() => {
                    if !matches!(result, Some(Ok(Ok(())))) { break; }
                }
                incoming = connection.accept_bi(), if streams.len() < CONCURRENT_STREAMS => {
                    let Ok((mut send, mut recv)) = incoming else { break; };
                    accepted += 1;
                    if accepted > 512 { break; }
                    let pacer = pacer.clone();
                    streams.spawn(async move {
                        let result = timeout(STREAM_DEADLINE, async {
                            // Echo bounded chunks as they arrive so paced request/response
                            // directions can overlap instead of doubling the suite duration.
                            let mut buffer = [0u8; 1024];
                            let mut received = 0usize;
                            while let Some(n) = recv.read(&mut buffer).await? {
                                received += n;
                                ensure!(received <= MAX_ECHO_BYTES, "echo payload exceeds limit");
                                write_payload(&mut send, &buffer[..n], pacer.as_deref()).await?;
                            }
                            send.finish()?;
                            // Keep the task slot until acknowledged, bounding queued response data.
                            send.stopped().await?;
                            Ok::<_, anyhow::Error>(())
                        }).await.context("stream deadline").and_then(|r| r);
                        if result.is_err() {
                            let _ = send.reset(1u32.into());
                            let _ = recv.stop(1u32.into());
                        }
                        result
                    });
                }
            }
        }
    };
    let _ = timeout(CONNECTION_LIFETIME, work).await;
    connection.close(0u32.into(), b"echo connection ended");
    packets.abort_all();
    while packets.join_next().await.is_some() {}
    streams.abort_all();
    while streams.join_next().await.is_some() {}
}

/// Explicit shutdown closes only this endpoint and joins/cancels its owned task sets.
pub async fn serve(
    endpoint: Endpoint,
    settings: session::Settings,
    shutdown: impl Future<Output = ()>,
) {
    serve_with_tunnel(endpoint, settings, None, shutdown).await;
}

pub async fn serve_with_tunnel(
    endpoint: Endpoint,
    mut settings: session::Settings,
    tunnel: Option<crate::config::Tunnel>,
    shutdown: impl Future<Output = ()>,
) {
    if tunnel.is_some() {
        settings.enable_tunnel();
    }
    let tunnel = tunnel.map(Arc::new);
    let settings = Arc::new(settings);
    tokio::pin!(shutdown);
    let mut connections = JoinSet::new();
    let pacer = Arc::new(Pacer::new(1.0));
    let fetch_pacer = Arc::new(crate::tcp_connect::Pacer::default());
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            _ = connections.join_next(), if !connections.is_empty() => {},
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break; };
                if connections.len() >= MAX_CONNECTIONS || endpoint.open_connections() >= MAX_TRACKED_CONNECTIONS {
                    incoming.refuse();
                } else if !incoming.remote_address_validated() {
                    let _ = incoming.retry();
                } else {
                    let pacer = (!incoming.remote_address().ip().is_loopback()).then(|| pacer.clone());
                    let settings = settings.clone();
                    let tunnel = tunnel.clone();
                    let fetch_pacer = fetch_pacer.clone();
                    connections.spawn(async move {
                        if let Ok(Ok(connection)) = timeout(CONNECT_DEADLINE, incoming).await {
                            serve_connection(connection, pacer, settings, tunnel, fetch_pacer).await;
                        }
                    });
                }
            }
        }
    }
    endpoint.close(0u32.into(), b"echo relay shutdown");
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    let _ = timeout(Duration::from_secs(1), endpoint.wait_idle()).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn concurrent_senders_share_one_pacing_budget() {
        let pacer = Arc::new(Pacer::new(1.0));
        let start = Instant::now();
        let mut jobs = JoinSet::new();
        for _ in 0..3 {
            let pacer = pacer.clone();
            jobs.spawn(async move {
                for _ in 0..4 {
                    pacer.wait(1024).await;
                }
            });
        }
        timeout(Duration::from_secs(2), async {
            while let Some(job) = jobs.join_next().await {
                job.unwrap();
            }
        })
        .await
        .unwrap();
        // Twelve KiB from three streams must not get three independent rate budgets.
        assert!(start.elapsed() >= Duration::from_millis(220));
    }
}
