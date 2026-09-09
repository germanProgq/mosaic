#[path = "../support/mod.rs"]
mod support;

use mosaic_core::{
    fetch, frame, quic, session,
    tcp_connect::{self, Request, Response},
};
use std::{
    sync::{Arc, atomic::AtomicU64},
    time::Duration,
};
use support::{Fixture, stop};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};

#[test]
fn destinations_reject_private_special_and_mixed_dns_answers() {
    for ip in [
        "0.1.2.3",
        "10.0.0.1",
        "100.64.0.1",
        "127.0.0.1",
        "169.254.169.254",
        "172.16.0.1",
        "192.168.1.1",
        "192.0.0.8",
        "192.0.2.1",
        "192.88.99.1",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "255.255.255.255",
    ] {
        assert!(!tcp_connect::public_ipv4(ip.parse().unwrap()), "{ip}");
    }
    for ip in ["1.1.1.1", "8.8.8.8", "93.184.216.34"] {
        assert!(tcp_connect::public_ipv4(ip.parse().unwrap()));
    }
    let mixed = [
        "1.1.1.1:443".parse().unwrap(),
        "127.0.0.1:443".parse().unwrap(),
    ];
    assert!(tcp_connect::checked_addresses(mixed.into_iter()).is_err());
    assert!(tcp_connect::checked_addresses(["[::1]:443".parse().unwrap()].into_iter()).is_err());
    for url in [
        "http://example.com",
        "https://user:secret@example.com",
        "https://example.com:8443",
        "https://127.1",
        "https://[::1]",
        "https://example.com/#fragment",
        "https://example.com\r\nHost: bad",
    ] {
        assert!(fetch::target(url).is_err());
    }
    assert!(fetch::target("https://example.com/path?q=value").is_ok());
}

#[tokio::test]
async fn fetch_requires_enabled_service_and_rejects_disallowed_and_private_targets() {
    let mut fixture = Fixture::new();
    let (tx, service) = fixture.start();
    let client = quic::connect(&fixture.client).await.unwrap();
    assert!(
        session::authorize_fetch(&client.connection, &fixture.client)
            .await
            .is_err()
    );
    let (diagnostic, _) = quic::connect_ready(&fixture.client).await.unwrap();
    quic::echo(&diagnostic.connection, b"after disabled fetch")
        .await
        .unwrap();
    drop(client);
    drop(diagnostic);
    stop(tx, service).await;
    fixture
        .relay
        .fetch
        .allow
        .push(mosaic_core::config::Destination {
            host: "localhost".into(),
            port: 443,
        });
    let endpoint = quic::relay_endpoint(&fixture.relay).unwrap();
    fixture.client.server.address = endpoint.local_addr().unwrap();
    let mut settings = session::Settings::load(&fixture.relay).unwrap();
    settings.enable_fetch(fixture.relay.fetch.clone());
    let (tx, rx) = tokio::sync::oneshot::channel();
    let service = tokio::spawn(quic::serve(endpoint, settings, async {
        let _ = rx.await;
    }));
    let client = quic::connect(&fixture.client).await.unwrap();
    session::authorize_fetch(&client.connection, &fixture.client)
        .await
        .unwrap();
    for host in ["not-allowed.invalid", "localhost"] {
        let (mut send, mut recv) = client.connection.open_bi().await.unwrap();
        frame::write_control(
            &mut send,
            &Request::OpenTcp {
                host: host.into(),
                port: 443,
            },
            4096,
        )
        .await
        .unwrap();
        assert!(matches!(
            timeout(
                Duration::from_secs(5),
                frame::read_control::<Response>(&mut recv, 4096)
            )
            .await
            .unwrap()
            .unwrap(),
            Response::TcpRejected
        ));
        frame::finish_control(&mut recv).await.unwrap();
    }
    drop(client);
    let (diagnostic, _) = quic::connect_ready(&fixture.client).await.unwrap();
    quic::echo(&diagnostic.connection, b"after rejected targets")
        .await
        .unwrap();
    drop(diagnostic);
    stop(tx, service).await;
}

async fn https_fixture(
    trusted: bool,
    name: &str,
    response: Vec<u8>,
    upload: Option<Vec<u8>>,
    limit: u64,
) -> anyhow::Result<fetch::Outcome> {
    let mut fixture = Fixture::new();
    let cert = rcgen::generate_simple_self_signed(vec![name.into()]).unwrap();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], key.into())
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let expected_upload = upload.clone().unwrap_or_default();
    let destination = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let Ok(mut stream) = tokio_rustls::TlsAcceptor::from(Arc::new(tls))
            .accept(socket)
            .await
        else {
            return;
        };
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            header.push(stream.read_u8().await.unwrap());
            assert!(header.len() < 16384);
        }
        assert!(String::from_utf8_lossy(&header).contains("host: example.com"));
        let mut body = vec![0; expected_upload.len()];
        stream.read_exact(&mut body).await.unwrap();
        assert_eq!(body, expected_upload);
        let _ = stream.write_all(&response).await;
        let _ = stream.shutdown().await;
    });
    let endpoint = quic::relay_endpoint(&fixture.relay).unwrap();
    fixture.client.server.address = endpoint.local_addr().unwrap();
    let mut settings = session::Settings::load(&fixture.relay).unwrap();
    settings.enable_fetch(fixture.relay.fetch.clone());
    let peer_endpoint = endpoint.clone();
    let relay = tokio::spawn(async move {
        let connection = peer_endpoint.accept().await.unwrap().await.unwrap();
        session::accept(&connection, &settings).await.unwrap();
        let (mut send, mut recv) = connection.accept_bi().await.unwrap();
        let Request::OpenTcp { host, port } = frame::read_control(&mut recv, 4096).await.unwrap();
        assert_eq!((host.as_str(), port), ("example.com", 443));
        tcp_connect::allowed(settings.fetch.as_ref().unwrap(), &host, port).unwrap();
        let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
        frame::write_control(
            &mut send,
            &Response::TcpReady {
                max_bytes: limit,
                timeout_s: 5,
            },
            4096,
        )
        .await
        .unwrap();
        let result = tcp_connect::forward(
            &mut send,
            &mut recv,
            tcp,
            &AtomicU64::new(limit),
            &tcp_connect::Pacer::default(),
        )
        .await;
        if result.is_err() {
            let _ = send.reset(1u32.into());
        }
        let _ = connection.closed().await;
    });
    let client = quic::connect(&fixture.client).await.unwrap();
    session::authorize_fetch(&client.connection, &fixture.client)
        .await
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    if trusted {
        roots.add(cert.cert.der().clone()).unwrap();
    }
    let tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let result = timeout(
        Duration::from_secs(7),
        fetch::request(
            &client.connection,
            4096,
            &fetch::target("https://example.com/fixture").unwrap(),
            upload,
            tls,
        ),
    )
    .await
    .unwrap();
    drop(client);
    timeout(Duration::from_secs(2), relay)
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(2), destination)
        .await
        .unwrap()
        .unwrap();
    endpoint.close(0u32.into(), b"fixture complete");
    result
}

#[tokio::test]
async fn verified_tls_http_chunks_and_upload_cross_real_quic_and_tcp() {
    let upload: Vec<u8> = (0..16384).map(|i| (i * 31 % 256) as u8).collect();
    let result = https_fixture(true, "example.com", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n".to_vec(), Some(upload), 100000).await.unwrap();
    assert_eq!(result.bytes, 5);
    assert_eq!(
        result.sha256,
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
    assert_eq!(result.uploaded_bytes, 16384);
}

#[tokio::test]
async fn destination_tls_and_truncated_or_redirected_http_fail() {
    let valid = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello".to_vec();
    assert!(
        https_fixture(false, "example.com", valid.clone(), None, 100000)
            .await
            .is_err()
    );
    assert!(
        https_fixture(true, "wrong.example.com", valid, None, 100000)
            .await
            .is_err()
    );
    for response in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nshort".as_slice(),
        b"HTTP/1.1 302 Found\r\nLocation: https://private.invalid/\r\nContent-Length: 0\r\n\r\n"
            .as_slice(),
    ] {
        assert!(
            https_fixture(true, "example.com", response.to_vec(), None, 100000)
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn opaque_tcp_byte_cap_resets_oversized_transfer() {
    let mut response =
        b"HTTP/1.1 200 OK\r\nContent-Length: 65536\r\nConnection: close\r\n\r\n".to_vec();
    response.extend(vec![42; 65536]);
    assert!(
        https_fixture(true, "example.com", response, None, 8192)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn request_budget_malformed_headers_and_session_deadline_close_fetch() {
    for case in ["requests", "header", "deadline", "datagram"] {
        let mut fixture = Fixture::new();
        fixture.relay.fetch.max_requests = 1;
        fixture.relay.fetch.timeout_s = 1;
        let endpoint = quic::relay_endpoint(&fixture.relay).unwrap();
        fixture.client.server.address = endpoint.local_addr().unwrap();
        let mut settings = session::Settings::load(&fixture.relay).unwrap();
        settings.enable_fetch(fixture.relay.fetch.clone());
        let (tx, rx) = tokio::sync::oneshot::channel();
        let service = tokio::spawn(quic::serve(endpoint, settings, async {
            let _ = rx.await;
        }));
        let client = quic::connect(&fixture.client).await.unwrap();
        session::authorize_fetch(&client.connection, &fixture.client)
            .await
            .unwrap();
        match case {
            "requests" => {
                let (mut send, mut recv) = client.connection.open_bi().await.unwrap();
                frame::write_control(
                    &mut send,
                    &Request::OpenTcp {
                        host: "disallowed.invalid".into(),
                        port: 443,
                    },
                    4096,
                )
                .await
                .unwrap();
                assert!(matches!(
                    frame::read_control::<Response>(&mut recv, 4096)
                        .await
                        .unwrap(),
                    Response::TcpRejected
                ));
                frame::finish_control(&mut recv).await.unwrap();
            }
            "header" => {
                let (mut send, _) = client.connection.open_bi().await.unwrap();
                send.write_all(&4097u32.to_be_bytes()).await.unwrap();
            }
            "datagram" => client
                .connection
                .send_datagram(frame::packet(0, b"invalid for fetch").unwrap().into())
                .unwrap(),
            _ => {}
        }
        timeout(Duration::from_secs(2), client.connection.closed())
            .await
            .unwrap();
        drop(client);
        let (diagnostic, _) = quic::connect_ready(&fixture.client).await.unwrap();
        quic::echo(&diagnostic.connection, b"healthy after fetch limit")
            .await
            .unwrap();
        drop(diagnostic);
        stop(tx, service).await;
    }
}
