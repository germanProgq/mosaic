#[allow(dead_code)]
#[path = "../support/mod.rs"]
mod support;
#[allow(dead_code)]
mod tunnel_pair;
use std::sync::atomic::Ordering;
use tunnel_pair::{CLIENT, REMOTE, ipv4, pair, payload};

#[tokio::test]
async fn full_mtu_packets_pass_and_oversize_packets_are_rejected() {
    let mut pair = pair(None).await;
    let full = ipv4(CLIENT, REMOTE, 17, 0x4000, &payload(1, 1080));
    assert_eq!(full.len(), 1100);
    pair.client.inject.send(full.clone()).await.unwrap();
    assert_eq!(pair.relay.next().await.unwrap(), full);
    let reply = ipv4(REMOTE, CLIENT, 17, 0x4000, &payload(2, 1080));
    pair.relay.inject.send(reply.clone()).await.unwrap();
    assert_eq!(pair.client.next().await.unwrap(), reply);
    let oversize = ipv4(CLIENT, REMOTE, 17, 0x4000, &payload(3, 1081));
    assert_eq!(oversize.len(), 1101);
    pair.client.inject.send(oversize).await.unwrap();
    assert!(pair.relay.quiet().await);
    assert_eq!(pair.client.counters.rejected.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn ipv4_fragments_of_a_large_datagram_pass_unchanged() {
    let mut pair = pair(None).await;
    let body = payload(4, 1408);
    let first = ipv4(CLIENT, REMOTE, 17, 0x2000, &body[..1072]);
    let second = ipv4(CLIENT, REMOTE, 17, 1072 / 8, &body[1072..]);
    pair.client.inject.send(first.clone()).await.unwrap();
    pair.client.inject.send(second.clone()).await.unwrap();
    assert_eq!(pair.relay.next().await.unwrap(), first);
    assert_eq!(pair.relay.next().await.unwrap(), second);
    let mut joined = pair.relay.counters.received.load(Ordering::SeqCst);
    joined += pair.client.counters.sent.load(Ordering::SeqCst);
    assert_eq!(joined, 4);
}

#[tokio::test]
async fn invalid_fragment_lengths_are_rejected() {
    let mut pair = pair(None).await;
    let uneven = ipv4(CLIENT, REMOTE, 17, 0x2000, &payload(5, 1001));
    pair.client.inject.send(uneven).await.unwrap();
    assert!(pair.relay.quiet().await);
    assert_eq!(pair.client.counters.rejected.load(Ordering::SeqCst), 1);
}
