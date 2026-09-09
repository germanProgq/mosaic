use crate::{
    config::ClientConfig,
    frame, quic, session,
    tcp_connect::{Request, Response},
};
use anyhow::{Context, Result, ensure};
use http_body_util::{BodyExt, Full};
use hyper::{Request as HttpRequest, body::Bytes};
use hyper_util::rt::TokioIo;
use ring::digest::{Context as Digest, SHA256};
use std::{
    future::Future,
    net::Ipv4Addr,
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::{Instant, Sleep, timeout},
};
use url::Url;

pub const MAX_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_UPLOAD_BYTES: u64 = 16 * 1024 * 1024;

struct Stream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    delay: Pin<Box<Sleep>>,
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buffer)
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.delay.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }
        match AsyncWrite::poll_write(
            Pin::new(&mut self.send),
            cx,
            &bytes[..bytes.len().min(4096)],
        ) {
            Poll::Ready(Ok(size)) => {
                self.delay.as_mut().reset(
                    Instant::now() + Duration::from_secs_f64((size + 128) as f64 / 80_000.0),
                );
                Poll::Ready(Ok(size))
            }
            result => result,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

pub struct Outcome {
    pub status: u16,
    pub bytes: u64,
    pub sha256: String,
    pub uploaded_bytes: usize,
    pub upload_sha256: String,
    pub egress: Option<Ipv4Addr>,
}

pub fn target(value: &str) -> Result<Url> {
    ensure!(
        value.len() <= 4096 && !value.chars().any(char::is_control),
        "invalid HTTPS URL"
    );
    let url = Url::parse(value).context("invalid HTTPS URL")?;
    ensure!(
        url.scheme() == "https"
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
            && url.port_or_known_default() == Some(443),
        "expected HTTPS URL without credentials or fragment on port 443"
    );
    ensure!(
        matches!(url.host(), Some(url::Host::Domain(host)) if host.contains('.') && !host.ends_with('.')),
        "expected destination DNS name"
    );
    Ok(url)
}

pub fn tls_config() -> rustls::ClientConfig {
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    tls.enable_early_data = false;
    tls.resumption = rustls::client::Resumption::disabled();
    tls
}

pub async fn run(config: &ClientConfig, value: &str, upload: Option<Vec<u8>>) -> Result<Outcome> {
    let url = target(value)?;
    ensure!(
        upload
            .as_ref()
            .is_none_or(|bytes| bytes.len() as u64 <= MAX_UPLOAD_BYTES),
        "upload exceeds 16 MiB"
    );
    let client = quic::connect(config).await?;
    session::authorize_fetch(&client.connection, config).await?;
    request(
        &client.connection,
        config.limits.max_control_bytes,
        &url,
        upload,
        tls_config(),
    )
    .await
}

pub async fn request(
    connection: &quinn::Connection,
    control_limit: usize,
    url: &Url,
    upload: Option<Vec<u8>>,
    tls: rustls::ClientConfig,
) -> Result<Outcome> {
    let url = target(url.as_str())?;
    let host = url.host_str().context("missing destination name")?;
    let (mut send, mut recv) = timeout(Duration::from_secs(10), async {
        let (mut send, recv) = connection.open_bi().await?;
        frame::write_control(
            &mut send,
            &Request::OpenTcp {
                host: host.into(),
                port: 443,
            },
            control_limit,
        )
        .await?;
        Ok::<_, anyhow::Error>((send, recv))
    })
    .await
    .context("OpenTcp deadline")??;
    let response = timeout(
        Duration::from_secs(10),
        frame::read_control(&mut recv, control_limit),
    )
    .await
    .context("OpenTcp deadline")??;
    let Response::TcpReady {
        max_bytes,
        timeout_s,
    } = response
    else {
        let _ = send.reset(1u32.into());
        anyhow::bail!("relay rejected destination");
    };
    ensure!(
        (1..=MAX_BYTES).contains(&max_bytes) && (1..=300).contains(&timeout_s),
        "invalid TCP limits"
    );
    timeout(Duration::from_secs(timeout_s), async {
        let name = rustls::pki_types::ServerName::try_from(host.to_owned())?;
        let stream = tokio_rustls::TlsConnector::from(Arc::new(tls))
            .connect(
                name,
                Stream {
                    send,
                    recv,
                    delay: Box::pin(tokio::time::sleep(Duration::ZERO)),
                },
            )
            .await
            .context("destination TLS verification failed")?;
        let (mut sender, driver) = hyper::client::conn::http1::Builder::new()
            .max_buf_size(16384)
            .handshake(TokioIo::new(stream))
            .await?;
        let method = if upload.is_some() { "POST" } else { "GET" };
        let upload = upload.unwrap_or_default();
        ensure!(
            upload.len() as u64 <= MAX_UPLOAD_BYTES && (upload.len() as u64) < max_bytes,
            "upload exceeds limit"
        );
        let uploaded_bytes = upload.len();
        let upload_sha256 = session::hex(ring::digest::digest(&SHA256, &upload).as_ref());
        let path = &url[url::Position::BeforePath..url::Position::AfterQuery];
        let request = HttpRequest::builder()
            .method(method)
            .uri(path)
            .header("Host", host)
            .header("Connection", "close")
            .header("Accept-Encoding", "identity")
            .body(Full::new(Bytes::from(upload)))?;
        let operation = async {
            let response = sender.send_request(request).await?;
            ensure!(
                response.status().is_success(),
                "HTTPS response was not successful"
            );
            let status = response.status().as_u16();
            let mut body = response.into_body();
            let mut hash = Digest::new(&SHA256);
            let mut bytes = 0u64;
            let mut preview = Vec::new();
            while let Some(frame) = body.frame().await {
                if let Ok(data) = frame?.into_data() {
                    bytes += data.len() as u64;
                    ensure!(
                        bytes + uploaded_bytes as u64 <= max_bytes,
                        "HTTPS body exceeds limit"
                    );
                    hash.update(&data);
                    if preview.len() < 64 {
                        preview.extend_from_slice(&data[..data.len().min(64 - preview.len())]);
                    }
                }
            }
            let egress = if host == "api.ipify.org" && bytes <= 64 {
                Some(
                    std::str::from_utf8(&preview)?
                        .trim()
                        .parse::<Ipv4Addr>()
                        .context("invalid egress address response")?,
                )
            } else {
                None
            };
            Ok(Outcome {
                status,
                bytes,
                sha256: session::hex(hash.finish().as_ref()),
                uploaded_bytes,
                upload_sha256,
                egress,
            })
        };
        tokio::pin!(operation);
        tokio::select! {
            result = &mut operation => result,
            result = driver => { result?; operation.await }
        }
    })
    .await
    .context("HTTPS deadline exceeded")?
}
