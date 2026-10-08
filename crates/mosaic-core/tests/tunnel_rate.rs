#[allow(dead_code)]
mod support;
use anyhow::Result;
use mosaic_core::{
    packet::Address,
    pump::{self, Counters, PacketIo},
    quic, session,
};
use std::{
    net::Ipv4Addr,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

const PACKETS: usize = 6000;
const PACKET_BYTES: usize = 1000;
const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 2);

fn ipv4(destination: Ipv4Addr, length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&(length as u16).to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 17;
    bytes[12..16].copy_from_slice(&[1, 1, 1, 1]);
    bytes[16..20].copy_from_slice(&destination.octets());
    let sum: u32 = bytes[..20]
        .chunks_exact(2)
        .map(|b| u32::from(u16::from_be_bytes([b[0], b[1]])))
        .sum();
    let sum = (sum & 0xffff) + (sum >> 16);
    let checksum = !(((sum & 0xffff) + (sum >> 16)) as u16);
    bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
    bytes
}

struct Source {
    packet: Vec<u8>,
    remaining: AtomicUsize,
}

impl PacketIo for Source {
    async fn receive(&self, bytes: &mut [u8]) -> Result<usize> {
        if self
            .remaining
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_err()
        {
            std::future::pending::<()>().await;
        }
        if self.remaining.load(Ordering::SeqCst).is_multiple_of(64) {
            tokio::task::yield_now().await;
        }
        bytes[..self.packet.len()].copy_from_slice(&self.packet);
        Ok(self.packet.len())
    }
    async fn send(&self, _: &[u8]) -> Result<()> {
        Ok(())
    }
}

#[derive(Default)]
struct Sink {
    bytes: AtomicU64,
}

impl PacketIo for Sink {
    async fn receive(&self, _: &mut [u8]) -> Result<usize> {
        std::future::pending().await
    }
    async fn send(&self, bytes: &[u8]) -> Result<()> {
        self.bytes.fetch_add(bytes.len() as u64, Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unpaced_tunnel_exceeds_the_former_one_megabit_ceiling() {
    let mut fixture = support::Fixture::new();
    let endpoint = quic::relay_endpoint(&fixture.relay).unwrap();
    fixture.client.server.address = endpoint.local_addr().unwrap();
    fixture.client.mode = "native_tun".into();
    fixture.client.limits.queue_packets = 2048;
    let mut settings = session::Settings::load(&fixture.relay).unwrap();
    settings.enable_tunnel();
    let source = Arc::new(Source {
        packet: ipv4(CLIENT, PACKET_BYTES),
        remaining: AtomicUsize::new(PACKETS),
    });
    let relay_source = source.clone();
    let relay = tokio::spawn(async move {
        let connection = endpoint.accept().await.unwrap().await.unwrap();
        let _ready = session::accept(&connection, &settings).await.unwrap();
        let _ = pump::run(
            &connection,
            relay_source.as_ref(),
            pump::Options {
                outbound: Address::Destination(CLIENT),
                inbound: Address::Source(CLIENT),
                queue_packets: 2048,
                max_mbps: None,
            },
            Arc::new(Counters::default()),
        )
        .await;
    });
    let client = quic::connect(&fixture.client).await.unwrap();
    session::authorize_tunnel(&client.connection, &fixture.client)
        .await
        .unwrap();
    let sink = Arc::new(Sink::default());
    let client_sink = sink.clone();
    let connection = client.connection.clone();
    let pump_task = tokio::spawn(async move {
        let _ = pump::run(
            &connection,
            client_sink.as_ref(),
            pump::Options {
                outbound: Address::Source(CLIENT),
                inbound: Address::Destination(CLIENT),
                queue_packets: 2048,
                max_mbps: None,
            },
            Arc::new(Counters::default()),
        )
        .await;
    });
    let start = Instant::now();
    let target = (PACKETS * PACKET_BYTES / 2) as u64;
    while sink.bytes.load(Ordering::SeqCst) < target && start.elapsed() < Duration::from_secs(20) {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let elapsed = start.elapsed().as_secs_f64();
    let delivered = sink.bytes.load(Ordering::SeqCst);
    let megabits = delivered as f64 * 8.0 / elapsed / 1_000_000.0;
    pump_task.abort();
    relay.abort();
    assert!(
        delivered >= target,
        "delivered {delivered} bytes in {elapsed:.2}s"
    );
    assert!(megabits > 8.0, "tunnel delivered only {megabits:.2} Mbit/s");
}

#[test]
fn configured_rate_limits_remain_validated() {
    assert!(pump::valid_rate(1.0));
    assert!(pump::valid_rate(pump::MAX_RATE_MBPS));
    assert!(!pump::valid_rate(0.0));
    assert!(!pump::valid_rate(f64::NAN));
    assert!(!pump::valid_rate(pump::MAX_RATE_MBPS * 2.0));
}
