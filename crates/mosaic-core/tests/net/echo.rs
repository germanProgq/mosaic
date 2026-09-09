use mosaic_core::{config::ClientConfig, quic, session};
use std::{net::SocketAddr, time::Duration};
use tokio::time::{Instant, timeout};
#[path = "../support/mod.rs"]
mod support;
use support::{Fixture, stop};

async fn valid(c: &ClientConfig) {
    let (client, _) = quic::connect_ready(c).await.unwrap();
    quic::echo(&client.connection, b"healthy after rejection")
        .await
        .unwrap();
}

#[tokio::test]
async fn all_sizes_three_streams_and_fresh_restart() {
    let mut f = Fixture::new();
    let mut address: Option<SocketAddr> = None;
    for _ in 0..2 {
        if let Some(address) = address {
            f.relay.listen = address;
        }
        let (tx, task) = f.start();
        address = Some(f.client.server.address);
        let (client, _) = quic::connect_ready(&f.client).await.unwrap();
        let tls = client
            .connection
            .handshake_data()
            .unwrap()
            .downcast::<quinn::crypto::rustls::HandshakeData>()
            .unwrap();
        assert_eq!(tls.protocol.as_deref(), Some(b"mosaic-poc/2".as_slice()));
        assert!(client.connection.max_datagram_size().unwrap() >= 1112);
        assert_eq!(
            quic::echo_suite(&client.connection, 1.0).await.unwrap(),
            quic::ECHO_SIZES.map(|n| (n, 100))
        );
        // Keep all three streams unfinished simultaneously, then finish and verify each.
        let mut streams = Vec::new();
        for n in 0..3u8 {
            let (mut send, recv) = client.connection.open_bi().await.unwrap();
            send.write_all(&[n]).await.unwrap();
            streams.push((send, recv, n));
        }
        for (mut send, mut recv, n) in streams {
            send.finish().unwrap();
            assert_eq!(
                timeout(quic::STREAM_DEADLINE, recv.read_to_end(1))
                    .await
                    .unwrap()
                    .unwrap(),
                [n]
            );
        }
        drop(client);
        stop(tx, task).await;
    }
}

#[tokio::test]
async fn bad_trust_name_and_alpn_are_tls_rejections_then_valid_echo() {
    let mut f = Fixture::new();
    let other = Fixture::new();
    let (tx, task) = f.start();
    let original_trust = f.client.tls.trust_cert.clone();
    for case in 0..3 {
        match case {
            0 => f.client.tls.trust_cert = other.client.tls.trust_cert.clone(),
            1 => f.client.server.name = "wrong.example.net".into(),
            2 => f.client.transport.alpn = "wrong-protocol".into(), // bypass schema to test real TLS ALPN negotiation
            _ => unreachable!(),
        }
        let start = Instant::now();
        let err = quic::connect(&f.client)
            .await
            .err()
            .expect("bad TLS must fail");
        assert!(start.elapsed() < quic::CONNECT_DEADLINE);
        assert!(
            matches!(
                err.downcast_ref::<quinn::ConnectionError>(),
                Some(quinn::ConnectionError::TransportError(_))
                    | Some(quinn::ConnectionError::ConnectionClosed(_))
            ),
            "expected TLS transport rejection, got {err}"
        );
        f.client.tls.trust_cert = original_trust.clone();
        f.client.server.name = "relay.example.net".into();
        f.client.transport.alpn = "mosaic-poc/2".into();
        valid(&f.client).await;
    }
    stop(tx, task).await;
}

#[tokio::test]
async fn silent_udp_path_hits_connection_deadline() {
    let mut f = Fixture::new();
    // A bound socket that never responds models filtered UDP without firewall changes.
    let blackhole = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    f.client.server.address = blackhole.local_addr().unwrap();
    let start = Instant::now();
    let err = quic::connect(&f.client).await.err().unwrap();
    assert!(err.to_string().contains("five seconds"));
    assert!(start.elapsed() < quic::CONNECT_DEADLINE + Duration::from_millis(250));
}

#[tokio::test]
async fn oversized_reset_and_unfinished_streams_are_bounded() {
    let mut f = Fixture::new();
    let (tx, task) = f.start();
    for case in 0..3 {
        let (client, _) = quic::connect_ready(&f.client).await.unwrap();
        let (mut send, mut recv) = client.connection.open_bi().await.unwrap();
        match case {
            0 => {
                send.write_all(&vec![7; quic::MAX_ECHO_BYTES + 1])
                    .await
                    .unwrap();
                send.finish().unwrap();
            }
            1 => {
                send.write_all(b"partial").await.unwrap();
                send.reset(1u32.into()).unwrap();
            }
            2 => {
                send.write_all(b"no FIN").await.unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            timeout(
                quic::STREAM_DEADLINE + Duration::from_secs(1),
                recv.read_to_end(quic::MAX_ECHO_BYTES)
            )
            .await
            .unwrap()
            .is_err()
        );
        drop(client);
        valid(&f.client).await;
    }
    stop(tx, task).await;
}

#[tokio::test]
async fn client_rejects_corrupt_or_oversized_echo_responses() {
    let mut f = Fixture::new();
    for oversized in [false, true] {
        let endpoint = quic::relay_endpoint(&f.relay).unwrap();
        f.client.server.address = endpoint.local_addr().unwrap();
        let settings = session::Settings::load(&f.relay).unwrap();
        let peer = tokio::spawn(async move {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            session::accept(&connection, &settings).await.unwrap();
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            recv.read_to_end(quic::MAX_ECHO_BYTES).await.unwrap();
            let payload = if oversized {
                vec![1; quic::MAX_ECHO_BYTES + 1]
            } else {
                b"corrupted".to_vec()
            };
            let _ = send.write_all(&payload).await;
            let _ = send.finish();
            let _ = send.stopped().await;
            let _ = connection.closed().await;
        });
        let (client, _) = quic::connect_ready(&f.client).await.unwrap();
        assert!(quic::echo(&client.connection, b"expected").await.is_err());
        drop(client);
        timeout(Duration::from_secs(2), peer)
            .await
            .unwrap()
            .unwrap();
    }
}
