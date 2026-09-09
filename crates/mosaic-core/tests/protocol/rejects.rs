use mosaic_core::{
    config::read_token,
    frame::{self, Control},
    quic, session,
};
use serde_json::{Value, json};
use std::time::Duration;
use tokio::time::timeout;
#[path = "../support/mod.rs"]
mod support;
use support::{Fixture, stop};

fn init(f: &Fixture) -> Value {
    json!({"type":"SessionInit", "version":2, "mode":"diagnostic", "token":session::hex(&read_token(&f.client.auth.token_file).unwrap()), "mtu":1100, "send_limit":1112})
}

async fn healthy(f: &Fixture) {
    let (client, ready) = quic::connect_ready(&f.client).await.unwrap();
    assert!(ready.send_limit >= 1112);
    quic::echo(&client.connection, b"healthy after rejected peer")
        .await
        .unwrap();
}

async fn rejected(client: &quic::ClientConnection) -> quinn::ApplicationClose {
    let error = timeout(Duration::from_secs(6), client.connection.closed())
        .await
        .unwrap();
    match error {
        quinn::ConnectionError::ApplicationClosed(error) => error,
        error => panic!("expected application rejection: {error}"),
    }
}

#[tokio::test]
async fn invalid_control_messages_never_reach_ready() {
    let mut f = Fixture::new();
    let (tx, task) = f.start();
    for case in [
        "missing-token",
        "wrong-token",
        "short-token",
        "long-token",
        "nonhex-token",
        "version",
        "unknown-field",
        "tunnel",
        "mtu",
        "small-limit",
        "wrong-type",
        "duplicate-field",
        "oversized",
        "zero-length",
        "truncated-header",
        "truncated-body",
        "length-mismatch",
        "no-message",
    ] {
        let client = quic::connect(&f.client).await.unwrap();
        let (mut send, _recv) = client.connection.open_bi().await.unwrap();
        let mut message = init(&f);
        match case {
            "missing-token" => {
                message.as_object_mut().unwrap().remove("token");
            }
            "wrong-token" => message["token"] = "00".repeat(32).into(),
            "short-token" => message["token"] = "ab".repeat(31).into(),
            "long-token" => message["token"] = "ab".repeat(33).into(),
            "nonhex-token" => message["token"] = "zz".repeat(32).into(),
            "version" => message["version"] = 3.into(),
            "unknown-field" => message["extra"] = true.into(),
            "tunnel" => message["mode"] = "tunnel".into(),
            "mtu" => message["mtu"] = 1280.into(),
            "small-limit" => message["send_limit"] = 1111.into(),
            "wrong-type" => message["type"] = "ClientReady".into(),
            _ => {}
        }
        match case {
            "oversized" => send.write_all(&u32::MAX.to_be_bytes()).await.unwrap(),
            "zero-length" => send.write_all(&0u32.to_be_bytes()).await.unwrap(),
            "truncated-header" => send.write_all(&[0, 0]).await.unwrap(),
            "truncated-body" => send.write_all(&[0, 0, 0, 100, b'{']).await.unwrap(),
            "length-mismatch" => send.write_all(&[0, 0, 0, 1, b'{', b'}']).await.unwrap(),
            "duplicate-field" => {
                let bytes =
                    serde_json::to_string(&message)
                        .unwrap()
                        .replacen('{', "{\"version\":2,", 1);
                send.write_all(&(bytes.len() as u32).to_be_bytes())
                    .await
                    .unwrap();
                send.write_all(bytes.as_bytes()).await.unwrap();
            }
            "no-message" => {}
            _ => frame::write_control(&mut send, &message, 4096)
                .await
                .unwrap(),
        }
        if case != "no-message" {
            send.finish().unwrap();
        }
        let error = rejected(&client).await;
        assert_eq!(
            error.error_code,
            if case == "small-limit" { 2u32 } else { 1u32 }.into(),
            "{case}"
        );
        assert!(
            !String::from_utf8_lossy(&error.reason).contains(&session::hex(
                &read_token(&f.client.auth.token_file).unwrap()
            ))
        );
        healthy(&f).await;
    }
    stop(tx, task).await;
}

#[tokio::test]
async fn ready_confirmation_and_early_data_are_enforced() {
    let mut f = Fixture::new();
    let (tx, task) = f.start();
    for case in [
        "early-datagram",
        "early-stream",
        "early-after-init",
        "wrong-id",
        "wrong-limit",
        "wrong-version",
        "extra-control",
        "missing-fin",
    ] {
        let client = quic::connect(&f.client).await.unwrap();
        let (mut send, mut recv) = client.connection.open_bi().await.unwrap();
        if case == "early-datagram" {
            client
                .connection
                .send_datagram(frame::packet(0, b"early").unwrap().into())
                .unwrap();
        } else if case == "early-stream" {
            send.write_all(b"raw unauthenticated echo").await.unwrap();
            send.finish().unwrap();
        } else {
            frame::write_control(&mut send, &init(&f), 4096)
                .await
                .unwrap();
            let mut ready: Value = frame::read_control(&mut recv, 4096).await.unwrap();
            if case == "early-after-init" {
                let (mut extra, _) = client.connection.open_bi().await.unwrap();
                extra.write_all(b"before ClientReady").await.unwrap();
                extra.finish().unwrap();
            } else {
                ready["type"] = "ClientReady".into();
                match case {
                    "wrong-id" => ready["session_id"] = "00".repeat(32).into(),
                    "wrong-limit" => ready["send_limit"] = 1111.into(),
                    "wrong-version" => ready["version"] = 1.into(),
                    _ => {}
                }
                frame::write_control(&mut send, &ready, 4096).await.unwrap();
                if case == "extra-control" {
                    send.write_all(&[0]).await.unwrap();
                }
                if case != "missing-fin" {
                    send.finish().unwrap();
                }
            }
        }
        rejected(&client).await;
        healthy(&f).await;
    }
    stop(tx, task).await;
}

#[tokio::test]
async fn packet_header_and_length_rejections_leave_relay_healthy() {
    let mut f = Fixture::new();
    let (tx, task) = f.start();
    for case in 0..5 {
        let (client, _) = quic::connect_ready(&f.client).await.unwrap();
        let mut packet = frame::packet(7, b"packet").unwrap();
        match case {
            0 => packet.truncate(11),
            1 => packet[0] = 3,
            2 => packet[1] = 0,
            3 => packet[3] += 1,
            4 => packet.resize(1113, 0),
            _ => unreachable!(),
        }
        client.connection.send_datagram(packet.into()).unwrap();
        rejected(&client).await;
        healthy(&f).await;
    }
    stop(tx, task).await;
}

#[tokio::test]
async fn datagrams_are_exact_and_session_ids_change_on_new_connections() {
    let mut f = Fixture::new();
    let (tx, task) = f.start();
    let (client, first) = quic::connect_ready(&f.client).await.unwrap();
    let options = quic::DatagramOptions {
        count: 1000,
        size: 1100,
        rate: 50,
    };
    assert_eq!(
        quic::datagram_suite(&client.connection, &options, 1.0)
            .await
            .unwrap(),
        1000
    );
    let (other, second) = quic::connect_ready(&f.client).await.unwrap();
    assert_ne!(first.session_id, second.session_id);
    quic::echo(&other.connection, b"fresh session")
        .await
        .unwrap();
    stop(tx, task).await;
}

#[tokio::test]
async fn client_rejects_invalid_ready_values_and_small_datagram_support() {
    let mut f = Fixture::new();
    for case in ["id", "size", "mode", "extra"] {
        let endpoint = quic::relay_endpoint(&f.relay).unwrap();
        f.client.server.address = endpoint.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            let _: Control = frame::read_control(&mut recv, 4096).await.unwrap();
            let mut ready = json!({"type":"SessionReady", "version":2, "mode":"diagnostic", "mtu":1100, "send_limit":1112, "session_id": session::identifier(&connection).unwrap()});
            match case {
                "id" => ready["session_id"] = "invalid".into(),
                "size" => ready["send_limit"] = 1111.into(),
                "mode" => ready["mode"] = "tunnel".into(),
                "extra" => ready["extra"] = true.into(),
                _ => unreachable!(),
            }
            frame::write_control(&mut send, &ready, 4096).await.unwrap();
            connection.closed().await;
        });
        let client = quic::connect(&f.client).await.unwrap();
        let error = session::authorize(&client.connection, &f.client)
            .await
            .err()
            .unwrap();
        if case == "size" {
            assert!(error.is::<session::SizeError>());
        }
        drop(client);
        timeout(Duration::from_secs(2), peer)
            .await
            .unwrap()
            .unwrap();
    }
    let (tx, task) = f.start();
    healthy(&f).await;
    stop(tx, task).await;
}

#[tokio::test]
async fn actual_small_peer_receive_limit_fails_before_ready() {
    let mut f = Fixture::new();
    let (tx, task) = f.start();
    let mut config = quic::client_config(&f.client).unwrap();
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(512));
    config.transport_config(std::sync::Arc::new(transport));
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(config);
    let connection = endpoint
        .connect(f.client.server.address, &f.client.server.name)
        .unwrap()
        .await
        .unwrap();
    let error = session::authorize(&connection, &f.client)
        .await
        .err()
        .unwrap();
    assert!(error.is::<session::SizeError>(), "{error}");
    endpoint.close(0u32.into(), b"fixture done");
    healthy(&f).await;
    stop(tx, task).await;
}

fn varint(bytes: &[u8], offset: &mut usize) -> usize {
    let length = 1 << (bytes[*offset] >> 6);
    let mut value = (bytes[*offset] & 0x3f) as usize;
    for byte in &bytes[*offset + 1..*offset + length] {
        value = (value << 8) | *byte as usize;
    }
    *offset += length;
    value
}

#[tokio::test]
async fn client_checks_unique_sequences_and_every_datagram_payload() {
    let mut f = Fixture::new();
    for case in [
        "reorder",
        "duplicate-only",
        "corruption",
        "unknown-sequence",
    ] {
        let endpoint = quic::relay_endpoint(&f.relay).unwrap();
        f.client.server.address = endpoint.local_addr().unwrap();
        let settings = session::Settings::load(&f.relay).unwrap();
        let peer = tokio::spawn(async move {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            session::accept(&connection, &settings).await.unwrap();
            let mut packets = Vec::new();
            for _ in 0..5 {
                packets.push(connection.read_datagram().await.unwrap());
            }
            match case {
                "reorder" => {
                    for packet in packets.into_iter().rev() {
                        connection.send_datagram(packet.clone()).unwrap();
                        connection.send_datagram(packet).unwrap();
                    }
                }
                "duplicate-only" => {
                    for _ in 0..5 {
                        connection.send_datagram(packets[0].clone()).unwrap();
                    }
                }
                _ => {
                    let mut packet = packets[0].to_vec();
                    if case == "corruption" {
                        packet[12] ^= 1;
                    } else {
                        packet[11] = 200;
                    }
                    connection.send_datagram(packet.into()).unwrap();
                }
            }
            connection.closed().await;
        });
        let (client, _) = quic::connect_ready(&f.client).await.unwrap();
        let result = quic::datagram_suite(
            &client.connection,
            &quic::DatagramOptions {
                count: 5,
                size: 64,
                rate: 50,
            },
            1.0,
        )
        .await;
        if case == "reorder" {
            assert_eq!(result.unwrap(), 5);
        } else {
            assert!(result.is_err());
        }
        drop(client);
        timeout(Duration::from_secs(2), peer)
            .await
            .unwrap()
            .unwrap();
    }
}

fn word(bytes: &[u8], offset: &mut usize) -> usize {
    let value = u16::from_be_bytes([bytes[*offset], bytes[*offset + 1]]) as usize;
    *offset += 2;
    value
}

#[tokio::test]
async fn captured_outer_handshake_exposes_server_name_and_alpn() {
    let mut f = Fixture::new();
    let capture = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    f.client.server.address = capture.local_addr().unwrap();
    let connection = quic::connect(&f.client);
    tokio::pin!(connection);
    let mut packet = vec![0; 2048];
    let length = tokio::select! {
        result = &mut connection => panic!("unexpected connection completion: {}", result.is_ok()),
        result = timeout(Duration::from_secs(2), capture.recv_from(&mut packet)) => result.unwrap().unwrap().0,
    };
    packet.truncate(length);
    assert_eq!(&packet[1..5], &[0, 0, 0, 1]);
    let dcid_length = packet[5] as usize;
    let dcid = packet[6..6 + dcid_length].to_vec();
    let mut offset = 6 + dcid_length;
    offset += 1 + packet[offset] as usize;
    let token_length = varint(&packet, &mut offset);
    offset += token_length;
    let protected_length = varint(&packet, &mut offset);
    packet.truncate(offset + protected_length);
    let suite = rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .unwrap()
        .quic_suite()
        .unwrap();
    let keys = suite.keys(&dcid, rustls::Side::Server, rustls::quic::Version::V1);
    let sample = packet[offset + 4..offset + 20].to_vec();
    let mut first = packet[0];
    keys.remote
        .header
        .decrypt_in_place(&sample, &mut first, &mut packet[offset..offset + 4])
        .unwrap();
    packet[0] = first;
    let number_length = (first & 3) as usize + 1;
    let mut number = 0u64;
    for byte in &packet[offset..offset + number_length] {
        number = (number << 8) | *byte as u64;
    }
    let (header, payload) = packet.split_at_mut(offset + number_length);
    let plaintext = keys
        .remote
        .packet
        .decrypt_in_place(number, header, payload)
        .unwrap();
    let mut offset = 0;
    let mut hello = Vec::new();
    while offset < plaintext.len() {
        match varint(plaintext, &mut offset) {
            0 | 1 => {}
            6 => {
                assert_eq!(varint(plaintext, &mut offset), hello.len());
                let length = varint(plaintext, &mut offset);
                hello.extend_from_slice(&plaintext[offset..offset + length]);
                offset += length;
            }
            kind => panic!("unexpected Initial frame {kind}"),
        }
    }
    assert_eq!(hello[0], 1);
    let token = session::hex(&read_token(&f.client.auth.token_file).unwrap());
    assert!(
        !hello
            .windows(token.len())
            .any(|bytes| bytes == token.as_bytes())
    );
    let mut offset = 4 + 2 + 32;
    offset += 1 + hello[offset] as usize;
    let suites = word(&hello, &mut offset);
    offset += suites;
    offset += 1 + hello[offset] as usize;
    let extension_length = word(&hello, &mut offset);
    let end = offset + extension_length;
    let mut server_name = None;
    let mut alpn = None;
    while offset < end {
        let kind = word(&hello, &mut offset);
        let length = word(&hello, &mut offset);
        let value = &hello[offset..offset + length];
        if kind == 0 {
            server_name = Some(std::str::from_utf8(&value[5..]).unwrap());
        }
        if kind == 16 {
            alpn = Some(std::str::from_utf8(&value[3..]).unwrap());
        }
        offset += length;
    }
    assert_eq!(server_name, Some("relay.example.net"));
    assert_eq!(alpn, Some("mosaic-poc/2"));
    println!(
        "{}",
        json!({"id":"session.handshake_visibility_capture", "status":"PASS", "scope":"loopback-capture", "server_name":server_name, "alpn":alpn, "token_in_client_hello":false})
    );
}
