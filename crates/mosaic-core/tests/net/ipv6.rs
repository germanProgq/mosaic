#[allow(dead_code)]
#[path = "../support/mod.rs"]
mod support;
#[allow(dead_code)]
mod tunnel_pair;
use mosaic_core::packet::{self, Address};
use std::sync::atomic::Ordering;
use tunnel_pair::{CLIENT, pair};

fn ipv6_packet() -> Vec<u8> {
    let mut bytes = vec![0u8; 48];
    bytes[0] = 0x60;
    bytes[4..6].copy_from_slice(&8u16.to_be_bytes());
    bytes[6] = 17;
    bytes[7] = 64;
    bytes[8] = 0xfd;
    bytes[24] = 0x20;
    bytes[25] = 0x01;
    bytes
}

#[tokio::test]
async fn ipv6_packets_are_rejected_in_both_directions() {
    let mut pair = pair(None).await;
    pair.client.inject.send(ipv6_packet()).await.unwrap();
    assert!(pair.relay.quiet().await);
    assert_eq!(pair.client.counters.rejected.load(Ordering::SeqCst), 1);
    pair.relay.inject.send(ipv6_packet()).await.unwrap();
    assert!(pair.client.quiet().await);
    assert_eq!(pair.relay.counters.rejected.load(Ordering::SeqCst), 1);
    assert!(packet::validate(&ipv6_packet(), Address::Source(CLIENT)).is_err());
}
