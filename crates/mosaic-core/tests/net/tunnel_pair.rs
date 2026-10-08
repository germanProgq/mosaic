use anyhow::Result;
use mosaic_core::{
    packet::Address,
    pump::{self, Counters, PacketIo},
    quic, session,
};
use std::{net::Ipv4Addr, sync::Arc, time::Duration};
use tokio::sync::{Mutex, mpsc};

pub const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 2);
pub const REMOTE: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);

pub struct ChannelTun {
    input: Mutex<mpsc::Receiver<Vec<u8>>>,
    output: mpsc::Sender<Vec<u8>>,
}

impl PacketIo for ChannelTun {
    async fn receive(&self, bytes: &mut [u8]) -> Result<usize> {
        let packet = self
            .input
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("fixture input closed"))?;
        let length = packet.len().min(bytes.len());
        bytes[..length].copy_from_slice(&packet[..length]);
        Ok(packet.len())
    }
    async fn send(&self, bytes: &[u8]) -> Result<()> {
        self.output.send(bytes.to_vec()).await?;
        Ok(())
    }
}

pub struct Side {
    pub inject: mpsc::Sender<Vec<u8>>,
    pub output: mpsc::Receiver<Vec<u8>>,
    pub counters: Arc<Counters>,
}

impl Side {
    pub async fn next(&mut self) -> Option<Vec<u8>> {
        tokio::time::timeout(Duration::from_secs(5), self.output.recv())
            .await
            .ok()
            .flatten()
    }
    pub async fn quiet(&mut self) -> bool {
        tokio::time::timeout(Duration::from_millis(300), self.output.recv())
            .await
            .is_err()
    }
}

fn side() -> (Side, ChannelTun) {
    let (inject, input) = mpsc::channel(4096);
    let (output, received) = mpsc::channel(4096);
    (
        Side {
            inject,
            output: received,
            counters: Arc::new(Counters::default()),
        },
        ChannelTun {
            input: Mutex::new(input),
            output,
        },
    )
}

pub struct Pair {
    pub client: Side,
    pub relay: Side,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    _fixture: super::support::Fixture,
}

impl Drop for Pair {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

pub async fn pair(max_mbps: Option<f64>) -> Pair {
    let mut fixture = super::support::Fixture::new();
    let endpoint = quic::relay_endpoint(&fixture.relay).unwrap();
    fixture.client.server.address = endpoint.local_addr().unwrap();
    fixture.client.mode = "native_tun".into();
    let mut settings = session::Settings::load(&fixture.relay).unwrap();
    settings.enable_tunnel();
    let (relay, relay_tun) = side();
    let (client, client_tun) = side();
    let relay_counters = relay.counters.clone();
    let relay_task = tokio::spawn(async move {
        let connection = endpoint.accept().await.unwrap().await.unwrap();
        let _ready = session::accept(&connection, &settings).await.unwrap();
        let _ = pump::run(
            &connection,
            &relay_tun,
            pump::Options {
                outbound: Address::Destination(CLIENT),
                inbound: Address::Source(CLIENT),
                queue_packets: 1024,
                max_mbps,
            },
            relay_counters,
        )
        .await;
        drop(endpoint);
    });
    let connection = quic::connect(&fixture.client).await.unwrap();
    let ready = session::authorize_tunnel(&connection.connection, &fixture.client)
        .await
        .unwrap();
    let client_counters = client.counters.clone();
    let client_task = tokio::spawn(async move {
        let _ = pump::run(
            &connection.connection,
            &client_tun,
            pump::Options {
                outbound: Address::Source(CLIENT),
                inbound: Address::Destination(CLIENT),
                queue_packets: 1024,
                max_mbps,
            },
            client_counters,
        )
        .await;
        drop(ready);
        drop(connection);
    });
    Pair {
        client,
        relay,
        tasks: vec![relay_task, client_task],
        _fixture: fixture,
    }
}

pub fn checksum(header: &mut [u8]) {
    header[10] = 0;
    header[11] = 0;
    let sum: u32 = header
        .chunks_exact(2)
        .map(|b| u32::from(u16::from_be_bytes([b[0], b[1]])))
        .sum();
    let sum = (sum & 0xffff) + (sum >> 16);
    let value = !(((sum & 0xffff) + (sum >> 16)) as u16);
    header[10..12].copy_from_slice(&value.to_be_bytes());
}

pub fn ipv4(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    protocol: u8,
    flags_offset: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut bytes = vec![0u8; 20];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    bytes[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
    bytes[6..8].copy_from_slice(&flags_offset.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = protocol;
    bytes[12..16].copy_from_slice(&source.octets());
    bytes[16..20].copy_from_slice(&destination.octets());
    checksum(&mut bytes);
    bytes.extend_from_slice(payload);
    bytes
}

pub fn udp(source: Ipv4Addr, destination: Ipv4Addr, port: u16, payload: &[u8]) -> Vec<u8> {
    let mut datagram = Vec::with_capacity(8 + payload.len());
    datagram.extend_from_slice(&40000u16.to_be_bytes());
    datagram.extend_from_slice(&port.to_be_bytes());
    datagram.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    datagram.extend_from_slice(&[0, 0]);
    datagram.extend_from_slice(payload);
    ipv4(source, destination, 17, 0x4000, &datagram)
}

pub fn payload(seed: usize, size: usize) -> Vec<u8> {
    (0..size)
        .map(|i| ((i * 31 + seed * 17) % 251) as u8)
        .collect()
}
