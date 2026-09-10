use crate::{
    frame,
    packet::{self, Address},
    session,
};
use anyhow::{Result, bail, ensure};
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

pub struct Options {
    pub outbound: Address,
    pub inbound: Address,
    pub queue_packets: usize,
    pub max_mbps: f64,
}

pub async fn run<T: PacketIo>(
    connection: &quinn::Connection,
    tun: &T,
    options: Options,
    counters: Arc<Counters>,
) -> Result<()> {
    ensure!(
        (1..=frame::MAX_QUEUE_PACKETS).contains(&options.queue_packets),
        "invalid packet queue limit"
    );
    ensure!(
        options.max_mbps.is_finite() && options.max_mbps > 0.0 && options.max_mbps <= 1.0,
        "invalid tunnel rate limit"
    );
    session::send_limit(connection)?;
    let (out_tx, mut out_rx) = mpsc::channel(options.queue_packets);
    let (in_tx, mut in_rx) = mpsc::channel(options.queue_packets);
    let schedule = Mutex::new(Instant::now());
    let schedule = &schedule;
    let pace = |size: usize| async move {
        let at = {
            let mut next = schedule.lock().await;
            let at = (*next).max(Instant::now());
            *next =
                at + Duration::from_secs_f64((size + 96) as f64 / (options.max_mbps * 50_000.0));
            at
        };
        tokio::time::sleep_until(at).await;
    };
    let read_tun = async {
        let mut buffer = [0; frame::MTU + 1];
        let mut sequence = 0u64;
        loop {
            let length = tun.receive(&mut buffer).await?;
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
            session::send_limit(connection)?;
            connection.send_datagram_wait(bytes.into()).await?;
            counters.sent.fetch_add(1, Ordering::Relaxed);
        }
        bail!("packet sender stopped")
    };
    let receive_packets = async {
        loop {
            let bytes = connection.read_datagram().await?;
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
            tun.send(&bytes).await?;
            counters.received.fetch_add(1, Ordering::Relaxed);
        }
        bail!("TUN writer stopped")
    };
    let result = tokio::select! {
        result = read_tun => result,
        result = send_packets => result,
        result = receive_packets => result,
        result = write_tun => result,
        stream = connection.accept_bi() => match stream {
            Err(error) => Err(error.into()),
            Ok(_) => Err(anyhow::anyhow!("streams are unavailable in tunnel mode")),
        },
    };
    connection.close(1u32.into(), b"tunnel stopped");
    result
}
