#[allow(dead_code)]
mod support;
use anyhow::Result;
use mosaic_core::{
    frame::{self, Control},
    packet::{self, Address},
    pump::{self, Counters, PacketIo},
    quic, session,
    transport::{PacketTooLarge, PacketTransport},
};
use std::{
    net::Ipv4Addr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 2);

fn ipv4(source: Ipv4Addr, destination: Ipv4Addr, length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&(length as u16).to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 17;
    bytes[12..16].copy_from_slice(&source.octets());
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

#[test]
fn serialized_vectors_are_unchanged() {
    assert_eq!(
        frame::packet(7, b"abc").unwrap(),
        [2, 1, 0, 3, 0, 0, 0, 0, 0, 0, 0, 7, b'a', b'b', b'c']
    );
    let inner = ipv4(CLIENT, Ipv4Addr::new(1, 1, 1, 1), 20);
    let encoded = packet::encode(9, &inner, Address::Source(CLIENT)).unwrap();
    assert_eq!(&encoded[..12], [2, 2, 0, 20, 0, 0, 0, 0, 0, 0, 0, 9]);
    assert_eq!(&encoded[12..], inner.as_slice());
    let control = serde_json::to_vec(&Control::SessionInit {
        version: 2,
        mode: "tunnel".into(),
        token: "00".repeat(32),
        mtu: 1100,
        send_limit: 1162,
    })
    .unwrap();
    assert_eq!(
        String::from_utf8(control).unwrap(),
        format!(
            "{{\"type\":\"SessionInit\",\"version\":2,\"mode\":\"tunnel\",\"token\":\"{}\",\"mtu\":1100,\"send_limit\":1162}}",
            "00".repeat(32)
        )
    );
}

struct Stalled {
    written: AtomicUsize,
}

impl PacketIo for Stalled {
    async fn receive(&self, _: &mut [u8]) -> Result<usize> {
        std::future::pending().await
    }
    async fn send(&self, _: &[u8]) -> Result<()> {
        self.written.fetch_add(1, Ordering::SeqCst);
        std::future::pending().await
    }
}

async fn tunnel_pair() -> (
    support::Fixture,
    quic::ClientConnection,
    quinn::Connection,
    session::Ready,
) {
    let mut fixture = support::Fixture::new();
    let endpoint = quic::relay_endpoint(&fixture.relay).unwrap();
    fixture.client.server.address = endpoint.local_addr().unwrap();
    fixture.client.mode = "native_tun".into();
    let mut settings = session::Settings::load(&fixture.relay).unwrap();
    settings.enable_tunnel();
    let accept = tokio::spawn(async move {
        let connection = endpoint.accept().await.unwrap().await.unwrap();
        let ready = session::accept(&connection, &settings).await.unwrap();
        (endpoint, connection, ready)
    });
    let client = quic::connect(&fixture.client).await.unwrap();
    session::authorize_tunnel(&client.connection, &fixture.client)
        .await
        .unwrap();
    let (endpoint, connection, ready) = accept.await.unwrap();
    std::mem::forget(endpoint);
    (fixture, client, connection, ready)
}

#[tokio::test]
async fn real_adapter_reports_sizes_and_rejects_oversize_packets() {
    let (_fixture, client, relay, _ready) = tunnel_pair().await;
    let limit = client.connection.max_packet_size().unwrap();
    assert!(limit >= frame::MTU + frame::PACKET_HEADER_BYTES);
    let error = client
        .connection
        .send_packet(vec![0; limit + 1])
        .await
        .unwrap_err();
    assert!(error.is::<PacketTooLarge>());
    client
        .connection
        .send_packet(vec![1; frame::MTU + frame::PACKET_HEADER_BYTES])
        .await
        .unwrap();
    let received = tokio::time::timeout(Duration::from_secs(5), relay.receive_packet())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, vec![1; frame::MTU + frame::PACKET_HEADER_BYTES]);
    PacketTransport::close(&relay, 3, b"fixture closed");
    let closed = tokio::time::timeout(Duration::from_secs(5), client.connection.receive_packet())
        .await
        .unwrap()
        .unwrap_err();
    assert!(mosaic_core::native::retryable(&closed));
}

#[tokio::test]
async fn real_adapter_queues_are_bounded_and_cancellation_closes() {
    let (_fixture, client, relay, _ready) = tunnel_pair().await;
    let stalled = Arc::new(Stalled {
        written: AtomicUsize::new(0),
    });
    let counters = Arc::new(Counters::default());
    let worker = {
        let connection = client.connection.clone();
        let stalled = stalled.clone();
        let counters = counters.clone();
        tokio::spawn(async move {
            pump::run(
                &connection,
                stalled.as_ref(),
                pump::Options {
                    outbound: Address::Source(CLIENT),
                    inbound: Address::Destination(CLIENT),
                    queue_packets: 8,
                    max_mbps: None,
                },
                counters,
            )
            .await
        })
    };
    let inner = ipv4(Ipv4Addr::new(1, 1, 1, 1), CLIENT, 200);
    for sequence in 0..200 {
        relay
            .send_packet(packet::encode(sequence, &inner, Address::Destination(CLIENT)).unwrap())
            .await
            .unwrap();
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        while counters.dropped.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(stalled.written.load(Ordering::SeqCst), 1);
    assert_eq!(counters.received.load(Ordering::SeqCst), 0);
    worker.abort();
    let _ = worker.await;
    client.connection.close(1u32.into(), b"cancelled");
    let closed = tokio::time::timeout(Duration::from_secs(5), relay.receive_packet())
        .await
        .unwrap();
    assert!(closed.is_err());
}

#[tokio::test]
async fn opened_streams_end_tunnel_mode() {
    let (_fixture, client, relay, _ready) = tunnel_pair().await;
    let opened = tokio::spawn(async move { relay.stream_opened().await });
    let (mut send, _recv) = client.connection.open_bi().await.unwrap();
    send.write_all(b"x").await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), opened)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_err());
}
