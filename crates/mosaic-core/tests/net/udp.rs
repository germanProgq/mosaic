#[allow(dead_code)]
#[path = "../support/mod.rs"]
mod support;
#[allow(dead_code)]
mod tunnel_pair;
use tunnel_pair::{CLIENT, REMOTE, pair, payload, udp};

const SIZES: [usize; 5] = [1, 64, 512, 1000, 1072];

#[tokio::test]
async fn udp_payloads_arrive_byte_exact_in_both_directions_at_one_megabit() {
    let mut pair = pair(Some(1.0)).await;
    for size in SIZES {
        let mut received = 0;
        for index in 0..100 {
            let outbound = udp(CLIENT, REMOTE, 7, &payload(index, size));
            pair.client.inject.send(outbound.clone()).await.unwrap();
            if pair.relay.next().await.as_deref() == Some(outbound.as_slice()) {
                received += 1;
            }
        }
        assert!(
            received >= 99,
            "client to relay size {size}: {received}/100"
        );
        let mut received = 0;
        for index in 0..100 {
            let inbound = udp(REMOTE, CLIENT, 40000, &payload(index + 1000, size));
            pair.relay.inject.send(inbound.clone()).await.unwrap();
            if pair.client.next().await.as_deref() == Some(inbound.as_slice()) {
                received += 1;
            }
        }
        assert!(
            received >= 99,
            "relay to client size {size}: {received}/100"
        );
    }
}
