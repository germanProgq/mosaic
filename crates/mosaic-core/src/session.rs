use crate::{
    config::{ClientConfig, RelayConfig, decode_token, read_token},
    frame::{self, Control},
    quic::CONNECT_DEADLINE,
};
use anyhow::{Context, Result, bail, ensure};
use quinn::Connection;
use subtle::ConstantTimeEq;
use tokio::time::timeout;

pub const SIZE_ERROR: u32 = 2;

pub struct Ready {
    pub session_id: String,
    pub send_limit: usize,
    pub mode: String,
    pub lease: Option<tokio::sync::OwnedSemaphorePermit>,
}

pub struct Settings {
    token: [u8; 32],
    pub control_limit: usize,
    pub queue_packets: usize,
    pub fetch: Option<crate::config::Fetch>,
    tunnel: Option<std::sync::Arc<tokio::sync::Semaphore>>,
}

impl Settings {
    pub fn enable_fetch(&mut self, fetch: crate::config::Fetch) {
        self.fetch = Some(fetch);
    }

    pub fn enable_tunnel(&mut self) {
        self.tunnel = Some(std::sync::Arc::new(tokio::sync::Semaphore::new(1)));
    }

    pub fn load(c: &RelayConfig) -> Result<Self> {
        ensure!(
            (1..=frame::MAX_QUEUE_PACKETS).contains(&c.limits.queue_packets)
                && (1..=frame::MAX_CONTROL_BYTES).contains(&c.limits.max_control_bytes),
            "invalid session resource limits"
        );
        Ok(Self {
            token: read_token(&c.auth.token_file)?,
            tunnel: None,
            fetch: None,
            control_limit: c.limits.max_control_bytes,
            queue_packets: c.limits.queue_packets.min(frame::MAX_QUEUE_PACKETS),
        })
    }
}

#[derive(Debug)]
pub struct SizeError;

#[derive(Debug)]
struct BusyError;

impl std::fmt::Display for BusyError {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str("tunnel already owned")
    }
}

impl std::error::Error for BusyError {}
impl std::fmt::Display for SizeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("datagram size limit must fit 1112 bytes")
    }
}
impl std::error::Error for SizeError {}

pub fn send_limit(connection: &Connection) -> Result<usize> {
    let size = connection.max_datagram_size().ok_or(SizeError)?;
    ensure!(size >= frame::MTU + frame::PACKET_HEADER_BYTES, SizeError);
    Ok(size)
}

pub fn identifier(connection: &Connection) -> Result<String> {
    let mut bytes = [0; 32];
    connection
        .export_keying_material(&mut bytes, b"mosaic session identifier", b"2")
        .map_err(|_| anyhow::anyhow!("session identifier unavailable"))?;
    Ok(hex(&bytes))
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub async fn authorize(connection: &Connection, c: &ClientConfig) -> Result<Ready> {
    authorize_mode(connection, c, "diagnostic").await
}

pub async fn authorize_tunnel(connection: &Connection, c: &ClientConfig) -> Result<Ready> {
    ensure!(
        c.mode == "isolated_tun" || c.mode == "native_tun",
        "TUN configuration required"
    );
    authorize_mode(connection, c, "tunnel").await
}

pub async fn authorize_fetch(connection: &Connection, c: &ClientConfig) -> Result<Ready> {
    authorize_mode(connection, c, "fetch").await
}

async fn authorize_mode(
    connection: &Connection,
    c: &ClientConfig,
    expected_mode: &str,
) -> Result<Ready> {
    let work = async {
        let local_limit = send_limit(connection)?;
        let token = read_token(&c.auth.token_file)?;
        let (mut send, mut recv) = connection.open_bi().await?;
        frame::write_control(
            &mut send,
            &Control::SessionInit {
                version: frame::VERSION,
                mode: expected_mode.into(),
                token: hex(&token),
                mtu: frame::MTU,
                send_limit: local_limit,
            },
            c.limits.max_control_bytes,
        )
        .await?;
        let Control::SessionReady {
            version,
            mode,
            mtu,
            send_limit: agreed,
            session_id,
        } = frame::read_control(&mut recv, c.limits.max_control_bytes).await?
        else {
            bail!("expected SessionReady")
        };
        ensure!(agreed >= frame::MTU + frame::PACKET_HEADER_BYTES, SizeError);
        ensure!(
            version == frame::VERSION
                && mode == expected_mode
                && mtu == frame::MTU
                && agreed <= local_limit
                && session_id == identifier(connection)?,
            "invalid SessionReady"
        );
        frame::write_control(
            &mut send,
            &Control::ClientReady {
                version,
                mode,
                mtu,
                send_limit: agreed,
                session_id: session_id.clone(),
            },
            c.limits.max_control_bytes,
        )
        .await?;
        send.finish()?;
        frame::finish_control(&mut recv).await?;
        Ok(Ready {
            session_id,
            send_limit: agreed,
            mode: expected_mode.into(),
            lease: None,
        })
    };
    let result = timeout(CONNECT_DEADLINE, async {
        tokio::select! {
            biased;
            _ = connection.read_datagram() => bail!("data before Ready"),
            result = work => result,
        }
    })
    .await
    .context("session exceeded five seconds")
    .and_then(|r| r);
    if result.is_err() {
        if matches!(connection.close_reason(), Some(quinn::ConnectionError::ApplicationClosed(ref e)) if e.error_code == SIZE_ERROR.into())
        {
            return Err(SizeError.into());
        }
        connection.close(1u32.into(), b"session rejected");
    }
    result
}

pub async fn accept(connection: &Connection, settings: &Settings) -> Result<Ready> {
    let result = timeout(CONNECT_DEADLINE, async {
        let (mut send, mut recv) = tokio::select! {
            biased;
            _ = connection.read_datagram() => bail!("data before Ready"),
            stream = connection.accept_bi() => stream?,
        };
        ensure!(recv.id().index() == 0, "expected initial control stream");
        let work = async {
            let Control::SessionInit {
                version,
                mode,
                token,
                mtu,
                send_limit: peer_limit,
            } = frame::read_control(&mut recv, settings.control_limit).await?
            else {
                bail!("expected SessionInit")
            };
            let supplied = decode_token(token.as_bytes())?;
            ensure!(
                bool::from(supplied.ct_eq(&settings.token)),
                "session rejected"
            );
            ensure!(
                version == frame::VERSION
                    && (mode == "diagnostic" || mode == "tunnel" || mode == "fetch")
                    && mtu == frame::MTU,
                "unsupported session"
            );
            ensure!(
                mode != "fetch" || settings.fetch.is_some(),
                "fetch mode unavailable"
            );
            ensure!(
                peer_limit >= frame::MTU + frame::PACKET_HEADER_BYTES,
                SizeError
            );
            let lease = if mode == "tunnel" {
                Some(
                    settings
                        .tunnel
                        .as_ref()
                        .context("tunnel mode unavailable")?
                        .clone()
                        .try_acquire_owned()
                        .map_err(|_| BusyError)?,
                )
            } else {
                None
            };
            let agreed = send_limit(connection)?.min(peer_limit);
            let id = identifier(connection)?;
            frame::write_control(
                &mut send,
                &Control::SessionReady {
                    version,
                    mode: mode.clone(),
                    mtu,
                    send_limit: agreed,
                    session_id: id.clone(),
                },
                settings.control_limit,
            )
            .await?;
            let Control::ClientReady {
                version: v,
                mode: m,
                mtu: size,
                send_limit: limit,
                session_id,
            } = frame::read_control(&mut recv, settings.control_limit).await?
            else {
                bail!("expected ClientReady")
            };
            ensure!(
                v == version && m == mode && size == mtu && limit == agreed && session_id == id,
                "invalid ClientReady"
            );
            frame::finish_control(&mut recv).await?;
            send.finish()?;
            Ok(Ready {
                session_id: id,
                send_limit: agreed,
                mode,
                lease,
            })
        };
        tokio::select! {
            biased;
            _ = connection.read_datagram() => bail!("data before Ready"),
            _ = connection.accept_bi() => bail!("stream before Ready"),
            result = work => result,
        }
    })
    .await
    .context("session exceeded five seconds")
    .and_then(|r| r);
    if let Err(error) = &result {
        if error.is::<BusyError>() {
            connection.close(3u32.into(), b"tunnel already owned");
        } else if error.is::<SizeError>() {
            connection.close(
                SIZE_ERROR.into(),
                b"datagram size limit must fit 1112 bytes",
            );
        } else {
            connection.close(1u32.into(), b"session rejected");
        }
    }
    result
}
