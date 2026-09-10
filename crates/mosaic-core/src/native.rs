use crate::{config::ClientConfig, packet::Address, pump, quic, session};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{future::Future, net::UdpSocket, sync::Arc, time::Duration};
use tokio::sync::watch;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    Failed,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Status {
    pub state: State,
    pub detail: String,
    pub ipv6: String,
}

impl Status {
    pub fn new(state: State, detail: &str) -> Self {
        Self {
            state,
            detail: detail.into(),
            ipv6: "blocked".into(),
        }
    }
}

pub trait Platform: pump::PacketIo {
    fn protect(&self, config: &ClientConfig) -> impl Future<Output = Result<()>> + Send;
    fn socket(&self, config: &ClientConfig) -> impl Future<Output = Result<UdpSocket>> + Send;
    fn configure(&self, config: &ClientConfig) -> impl Future<Output = Result<()>> + Send;
    fn verify(&self) -> impl Future<Output = Result<()>> + Send;
    fn discard(&self) -> impl Future<Output = Result<()>> + Send;
}

pub fn retry_delay(attempt: u32, random: u16) -> Duration {
    let limit = 1000u64 << attempt.min(3);
    Duration::from_millis(limit * 4 / 5 + u64::from(random) * (limit / 5) / u64::from(u16::MAX))
}

pub fn retryable(error: &anyhow::Error) -> bool {
    if let Some(error) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<quinn::ConnectionError>())
    {
        return matches!(
            error,
            quinn::ConnectionError::TimedOut
                | quinn::ConnectionError::Reset
                | quinn::ConnectionError::ConnectionClosed(_)
                | quinn::ConnectionError::LocallyClosed
        ) || matches!(error, quinn::ConnectionError::ApplicationClosed(close) if close.error_code == 3u32.into());
    }
    error.is::<tokio::time::error::Elapsed>() || error.is::<std::io::Error>()
}

pub async fn run<P: Platform>(
    config: &ClientConfig,
    platform: &P,
    status: watch::Sender<Status>,
    mut stop: watch::Receiver<bool>,
    mut path: watch::Receiver<u64>,
) -> Result<()> {
    config.validate()?;
    ensure!(
        config.mode == "native_tun",
        "native TUN configuration required"
    );
    config.check_credentials()?;
    let address = crate::config::tunnel(config.tunnel.as_ref().unwrap())?;
    status.send_replace(Status::new(
        State::Connecting,
        "Preparing protected networking",
    ));
    platform.protect(config).await?;
    let work = async {
        let mut attempt = 0;
        loop {
            if *stop.borrow() { return Ok(()); }
            platform.discard().await?;
            let connect = async {
                let socket = platform.socket(config).await?;
                let client = quic::connect_socket(config, socket).await?;
                session::authorize_tunnel(&client.connection, config).await?;
                Ok::<_, anyhow::Error>(client)
            };
            let connected = tokio::select! {
                biased;
                _ = stop.changed() => return Ok(()),
                _ = path.changed() => continue,
                result = connect => result,
            };
            match connected {
                Ok(client) => {
                    tokio::select! {
                        biased;
                        _ = stop.changed() => return Ok(()),
                        _ = path.changed() => continue,
                        result = platform.configure(config) => result?,
                    }
                    platform.discard().await?;
                    platform.verify().await?;
                    status.send_replace(Status::new(State::Connected, "IPv4 routing and tunnel DNS are ready; IPv6 is blocked"));
                    let counters = Arc::new(pump::Counters::default());
                    let options = pump::Options { outbound: Address::Source(address), inbound: Address::Destination(address), queue_packets: config.limits.queue_packets, max_mbps: 1.0 };
                    let monitor = async {
                        loop {
                            tokio::time::sleep(Duration::from_secs(2)).await;
                            platform.verify().await?;
                        }
                        #[allow(unreachable_code)]
                        Ok::<(), anyhow::Error>(())
                    };
                    tokio::select! {
                        biased;
                        _ = stop.changed() => return Ok(()),
                        _ = path.changed() => {},
                        result = monitor => result?,
                        result = pump::run(&client.connection, platform, options, counters) => {
                            if let Err(error) = result && !retryable(&error) { return Err(error); }
                        },
                    }
                    attempt = 0;
                }
                Err(error) if !retryable(&error) => return Err(anyhow::anyhow!("Relay identity, authorization, packet size or configuration rejected; correct the configuration and reconnect")),
                Err(_) => {},
            }
            platform.discard().await?;
            status.send_replace(Status::new(State::Reconnecting, "Relay unavailable; traffic remains protected"));
            let mut random = [0; 2];
            ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut random).map_err(|_| anyhow::anyhow!("retry randomness unavailable"))?;
            let delay = retry_delay(attempt, u16::from_ne_bytes(random));
            attempt = attempt.saturating_add(1);
            tokio::select! {
                biased;
                _ = stop.changed() => return Ok(()),
                _ = path.changed() => {},
                _ = tokio::time::sleep(delay) => {},
            }
        }
    }.await;
    let work = work.and(platform.discard().await);
    if work.is_err() {
        status.send_replace(Status::new(
            State::Failed,
            "Connection failed; protection is retained until explicit disconnect",
        ));
    }
    work
}
