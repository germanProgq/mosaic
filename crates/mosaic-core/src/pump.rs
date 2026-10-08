use crate::{
    frame,
    packet::{self, Address},
    transport::{PacketTransport, checked_size},
};
use anyhow::{Context, Result, bail, ensure};
use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{Mutex, mpsc},
    time::Instant,
};

pub trait PacketIo: Send + Sync {
    fn receive(&self, bytes: &mut [u8]) -> impl Future<Output = Result<usize>> + Send;
    fn send(&self, bytes: &[u8]) -> impl Future<Output = Result<()>> + Send;
}

#[derive(Default)]
pub struct Counters {
    pub sent: AtomicU64,
    pub received: AtomicU64,
    pub rejected: AtomicU64,
    pub dropped: AtomicU64,
}

pub const MAX_RATE_MBPS: f64 = 10_000.0;

pub struct Options {
    pub outbound: Address,
    pub inbound: Address,
    pub queue_packets: usize,
    pub max_mbps: Option<f64>,
}

#[derive(Debug)]
pub struct TunError;

impl std::fmt::Display for TunError {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str("tunnel device failed")
    }
}

impl std::error::Error for TunError {}

pub fn valid_rate(max_mbps: f64) -> bool {
    max_mbps.is_finite() && max_mbps > 0.0 && max_mbps <= MAX_RATE_MBPS
}

pub async fn run<T: PacketIo, C: PacketTransport>(
    connection: &C,
    tun: &T,
    options: Options,
    counters: Arc<Counters>,
) -> Result<()> {
    ensure!(
        (1..=frame::MAX_QUEUE_PACKETS).contains(&options.queue_packets),
        "invalid packet queue limit"
    );
    ensure!(
        options.max_mbps.is_none_or(valid_rate),
        "invalid tunnel rate limit"
    );
    checked_size(connection.max_packet_size())?;
    let (out_tx, mut out_rx) = mpsc::channel(options.queue_packets);
    let (in_tx, mut in_rx) = mpsc::channel(options.queue_packets);
    let schedule = Mutex::new(Instant::now());
    let schedule = &schedule;
    let pace = |size: usize| async move {
        let Some(max_mbps) = options.max_mbps else {
            return;
        };
        let at = {
            let mut next = schedule.lock().await;
            let at = (*next).max(Instant::now());
            *next = at + Duration::from_secs_f64((size + 96) as f64 / (max_mbps * 125_000.0));
            at
        };
        tokio::time::sleep_until(at).await;
    };
    let read_tun = async {
        let mut buffer = [0; frame::MTU + 1];
        let mut sequence = 0u64;
        loop {
            let length = tun.receive(&mut buffer).await.context(TunError)?;
            ensure!(
                length > 0 && length <= buffer.len(),
                "TUN reader stopped or returned invalid length"
            );
            let bytes = match packet::encode(sequence, &buffer[..length], options.outbound) {
                Ok(bytes) => bytes,
                Err(_) => {
                    counters.rejected.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            };
            sequence = sequence.wrapping_add(1);
            if out_tx.try_send(bytes).is_err() {
                counters.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    };
    let send_packets = async {
        while let Some(bytes) = out_rx.recv().await {
            pace(bytes.len()).await;
            connection.send_packet(bytes).await?;
            counters.sent.fetch_add(1, Ordering::Relaxed);
        }
        bail!("packet sender stopped")
    };
    let receive_packets = async {
        loop {
            let bytes = connection.receive_packet().await?;
            let payload = match packet::decode(&bytes, options.inbound) {
                Ok((_, payload)) => payload,
                Err(_) => {
                    counters.rejected.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            };
            if in_tx.try_send(payload.to_vec()).is_err() {
                counters.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    };
    let write_tun = async {
        while let Some(bytes) = in_rx.recv().await {
            pace(bytes.len()).await;
            tun.send(&bytes).await.context(TunError)?;
            counters.received.fetch_add(1, Ordering::Relaxed);
        }
        bail!("TUN writer stopped")
    };
    let result = tokio::select! {
        result = read_tun => result,
        result = send_packets => result,
        result = receive_packets => result,
        result = write_tun => result,
        result = connection.stream_opened() => result,
    };
    connection.close(1, b"tunnel stopped");
    result
}
