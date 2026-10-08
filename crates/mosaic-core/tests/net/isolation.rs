#[path = "../support/mod.rs"]
mod support;

use mosaic_core::{
    frame,
    packet::{self, Address},
    pump::{self, PacketIo},
    quic, session,
};
use std::{
    net::Ipv4Addr,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio::{
    sync::{Mutex, mpsc},
    time::timeout,
};

fn ip() -> Ipv4Addr {
    Ipv4Addr::new(10, 77, 0, 2)
}

fn checksum(bytes: &mut [u8]) {
    bytes[10..12].fill(0);
    let size = usize::from(bytes[0] & 15) * 4;
    let sum: u32 = bytes[..size]
        .chunks_exact(2)
        .map(|b| u32::from(u16::from_be_bytes([b[0], b[1]])))
        .sum();
    let sum = (sum & 0xffff) + (sum >> 16);
    let sum = !((sum & 0xffff) + (sum >> 16)) as u16;
    bytes[10..12].copy_from_slice(&sum.to_be_bytes());
}

fn payload() -> Vec<u8> {
    let mut bytes = vec![0; 36];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&36u16.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 1;
    bytes[12..16].copy_from_slice(&ip().octets());
    bytes[16..20].copy_from_slice(&[10, 77, 0, 1]);
    checksum(&mut bytes);
    bytes
}

#[test]
fn ipv4_validation_rejects_malformed_and_spoofed_packets() {
    let bytes = payload();
    let source = Address::Source(ip());
    packet::validate(&bytes, source).unwrap();
    let mut bad = Vec::new();
    for length in [0, 1, 19, 25] {
        bad.push(bytes[..length].to_vec());
    }
    for (offset, value) in [
        (0, 0x65),
        (0, 0x44),
        (0, 0x4f),
        (2, 1),
        (12, 11),
        (10, 12),
        (6, 0x80),
        (6, 0x60),
    ] {
        let mut fixture = bytes.clone();
        fixture[offset] = value;
        if offset != 0 && offset != 10 {
            checksum(&mut fixture);
        }
        bad.push(fixture);
    }
    let mut oversized = vec![0; 1101];
    oversized[..36].copy_from_slice(&bytes);
    bad.push(oversized);
    for bytes in bad {
        assert!(packet::validate(&bytes, source).is_err());
    }
    assert!(packet::validate(&bytes, Address::Destination(ip())).is_err());
    let encoded = packet::encode(u64::MAX, &bytes, source).unwrap();
    assert_eq!(
        packet::decode(&encoded, source).unwrap(),
        (u64::MAX, bytes.as_slice())
    );
    for offset in [0, 1, 2, 3] {
        let mut bad = encoded.clone();
        bad[offset] ^= 0xff;
        assert!(packet::decode(&bad, source).is_err());
    }
    assert!(frame::read_packet(&encoded).is_err());
    assert!(packet::decode(&frame::packet(0, &bytes).unwrap(), source).is_err());
}

#[test]
fn valid_fragments_and_ipv4_options_are_preserved() {
    for flags in [0x2000u16, 0x2002, 0x0004] {
        let mut bytes = payload();
        bytes[6..8].copy_from_slice(&flags.to_be_bytes());
        checksum(&mut bytes);
        packet::validate(&bytes, Address::Source(ip())).unwrap();
    }
    let mut options = payload();
    options[0] = 0x46;
    checksum(&mut options);
    packet::validate(&options, Address::Source(ip())).unwrap();
    let mut truncated = payload();
    truncated.pop();
    truncated[3] = 35;
    truncated[6] = 0x20;
    checksum(&mut truncated);
    assert!(packet::validate(&truncated, Address::Source(ip())).is_err());
}

struct Packets {
    input: Mutex<mpsc::Receiver<Vec<u8>>>,
    output: mpsc::Sender<Vec<u8>>,
}
impl PacketIo for Packets {
    async fn receive(&self, bytes: &mut [u8]) -> anyhow::Result<usize> {
        let packet = self
            .input
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("input stopped"))?;
        bytes[..packet.len()].copy_from_slice(&packet);
        Ok(packet.len())
    }
    async fn send(&self, bytes: &[u8]) -> anyhow::Result<()> {
        self.output.send(bytes.to_vec()).await?;
        Ok(())
    }
}

#[tokio::test]
async fn inherited_custom_socket_and_tunnel_lease_use_real_quic() {
    let mut fixture = support::Fixture::new();
    let endpoint = quic::relay_endpoint(&fixture.relay).unwrap();
    fixture.client.server.address = endpoint.local_addr().unwrap();
    fixture.client.mode = "isolated_tun".into();
    let mut settings = session::Settings::load(&fixture.relay).unwrap();
    settings.enable_tunnel();
    let settings = Arc::new(settings);
    let server_endpoint = endpoint.clone();
    let settings_task = settings.clone();
    let server = tokio::spawn(async move {
        let connection = server_endpoint.accept().await.unwrap().await.unwrap();
        let ready = session::accept(&connection, &settings_task).await.unwrap();
        (connection, ready)
    });
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let original_port = socket.local_addr().unwrap().port();
    let client = quic::connect_socket(&fixture.client, socket).await.unwrap();
    session::authorize_tunnel(&client.connection, &fixture.client)
        .await
        .unwrap();
    let (connection, ready) = server.await.unwrap();
    assert_eq!(connection.remote_address().port(), original_port);
    assert_eq!(ready.mode, "tunnel");
    let settings_task = settings.clone();
    let server_endpoint = endpoint.clone();
    let rejected = tokio::spawn(async move {
        let connection = server_endpoint.accept().await.unwrap().await.unwrap();
        assert!(session::accept(&connection, &settings_task).await.is_err());
    });
    let second = quic::connect(&fixture.client).await.unwrap();
    assert!(
        session::authorize_tunnel(&second.connection, &fixture.client)
            .await
            .is_err()
    );
    rejected.await.unwrap();
    drop(ready);
    let server_endpoint = endpoint.clone();
    let next = tokio::spawn(async move {
        let connection = server_endpoint.accept().await.unwrap().await.unwrap();
        let ready = session::accept(&connection, &settings).await.unwrap();
        (connection, ready)
    });
    let third = quic::connect(&fixture.client).await.unwrap();
    session::authorize_tunnel(&third.connection, &fixture.client)
        .await
        .unwrap();
    let _next = next.await.unwrap();
    endpoint.close(0u32.into(), b"test complete");
}

#[tokio::test]
async fn packet_pumps_are_independent_reject_bad_input_and_cancel() {
    let mut fixture = support::Fixture::new();
    let endpoint = quic::relay_endpoint(&fixture.relay).unwrap();
    fixture.client.server.address = endpoint.local_addr().unwrap();
    let settings = session::Settings::load(&fixture.relay).unwrap();
    let server_endpoint = endpoint.clone();
    let accept = tokio::spawn(async move {
        let connection = server_endpoint.accept().await.unwrap().await.unwrap();
        session::accept(&connection, &settings).await.unwrap();
        connection
    });
    let (client, _) = quic::connect_ready(&fixture.client).await.unwrap();
    let server = accept.await.unwrap();
    let (tx, input) = mpsc::channel(4);
    let (output, mut rx) = mpsc::channel(4);
    let tun = Arc::new(Packets {
        input: Mutex::new(input),
        output,
    });
    let counters = Arc::new(pump::Counters::default());
    let job = tokio::spawn({
        let tun = tun.clone();
        let counters = counters.clone();
        let connection = client.connection.clone();
        async move {
            pump::run(
                &connection,
                tun.as_ref(),
                pump::Options {
                    outbound: Address::Source(ip()),
                    inbound: Address::Source(ip()),
                    queue_packets: 2,
                    max_mbps: Some(1.0),
                },
                counters,
            )
            .await
        }
    });
    tx.send(vec![0; 20]).await.unwrap();
    server.send_datagram(vec![0; 20].into()).unwrap();
    timeout(Duration::from_secs(2), async {
        while counters.rejected.load(Ordering::Relaxed) < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(rx.try_recv().is_err());
    let valid = payload();
    for sequence in 0..20 {
        server
            .send_datagram(
                packet::encode(sequence, &valid, Address::Source(ip()))
                    .unwrap()
                    .into(),
            )
            .unwrap();
        assert_eq!(
            timeout(Duration::from_secs(2), rx.recv())
                .await
                .unwrap()
                .unwrap(),
            valid
        );
        tx.send(valid.clone()).await.unwrap();
        let reply = timeout(Duration::from_secs(2), server.read_datagram())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            packet::decode(&reply, Address::Source(ip())).unwrap(),
            (sequence, valid.as_slice())
        );
    }
    assert_eq!(counters.sent.load(Ordering::Relaxed), 20);
    assert_eq!(counters.received.load(Ordering::Relaxed), 20);
    client.connection.close(0u32.into(), b"cancel");
    assert!(
        timeout(Duration::from_secs(2), job)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    endpoint.close(0u32.into(), b"test complete");
}

#[tokio::test]
async fn diagnostic_service_rejects_tunnel_and_still_echoes() {
    let mut fixture = support::Fixture::new();
    let (stop, service) = fixture.start();
    fixture.client.mode = "isolated_tun".into();
    let client = quic::connect(&fixture.client).await.unwrap();
    assert!(
        session::authorize_tunnel(&client.connection, &fixture.client)
            .await
            .is_err()
    );
    let (diagnostic, _) = quic::connect_ready(&fixture.client).await.unwrap();
    quic::echo(&diagnostic.connection, b"after tunnel rejection")
        .await
        .unwrap();
    support::stop(stop, service).await;
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires root on a dedicated Linux test host with ip, ping and /dev/net/tun"]
fn linux_namespace_socket_and_tun_ping() {
    use mosaic_core::{config::ClientConfig, linux, tun::Tun};
    use std::{
        fs,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::process::CommandExt,
        },
        process::{Command, Stdio},
    };
    assert_eq!(unsafe { libc::geteuid() }, 0, "Linux root fixture required");
    if let Ok(value) = std::env::var("MOSAIC_FIXTURE_FD") {
        let socket = unsafe { std::net::UdpSocket::from_raw_fd(value.parse().unwrap()) };
        linux::check(unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) })
            .unwrap();
        let transport = fs::read_link(format!("/proc/self/fd/{}", socket.as_raw_fd())).unwrap();
        let expected: u64 = std::env::var("MOSAIC_FIXTURE_COOKIE")
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(linux::cookie(&socket).unwrap(), expected);
        let inside = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        assert_ne!(linux::cookie(&inside).unwrap(), expected);
        drop(inside);
        linux::command("ip", &["link", "set", "lo", "up"]).unwrap();
        let config = ClientConfig::load(std::path::Path::new(
            &std::env::var("MOSAIC_FIXTURE_CONFIG").unwrap(),
        ))
        .unwrap();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let client = quic::connect_socket(&config, socket).await.unwrap();
                session::authorize_tunnel(&client.connection, &config)
                    .await
                    .unwrap();
                let tun = Tun::create(config.tunnel.as_ref().unwrap()).unwrap();
                let counters = Arc::new(pump::Counters::default());
                let work = pump::run(
                    &client.connection,
                    &tun,
                    pump::Options {
                        outbound: Address::Source(ip()),
                        inbound: Address::Destination(ip()),
                        queue_packets: 4,
                        max_mbps: Some(1.0),
                    },
                    counters.clone(),
                );
                let mut ping = Command::new("ping")
                    .args(["-n", "-c", "20", "-i", "0.2", "-W", "2", "10.77.0.1"])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap();
                for descriptor in fs::read_dir(format!("/proc/{}/fd", ping.id())).unwrap() {
                    assert_ne!(
                        fs::read_link(descriptor.unwrap().path()).ok(),
                        Some(transport.clone())
                    );
                }
                let result = timeout(Duration::from_secs(15), async {
                    tokio::pin!(work);
                    loop {
                        tokio::select! {
                            result = &mut work => panic!("packet pump stopped: {result:?}"),
                            _ = tokio::time::sleep(Duration::from_millis(20)) => {
                                if let Some(status) = ping.try_wait().unwrap() { return status; }
                            }
                        }
                    }
                })
                .await;
                let _ = ping.kill();
                let _ = ping.wait();
                assert!(result.unwrap().success());
                assert_eq!(counters.sent.load(Ordering::Relaxed), 20);
                assert_eq!(counters.received.load(Ordering::Relaxed), 20);
                assert_eq!(counters.rejected.load(Ordering::Relaxed), 2);
            });
        return;
    }
    let links_before = Command::new("ip")
        .args(["-j", "link", "show"])
        .output()
        .unwrap();
    assert!(links_before.status.success());
    let mut fixture = support::Fixture::new();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let endpoint = quic::relay_endpoint(&fixture.relay).unwrap();
        fixture.client.server.address = endpoint.local_addr().unwrap();
        let root = fixture.client.auth.token_file.parent().unwrap().parent().unwrap();
        let mut config: serde_json::Value = serde_json::from_str(include_str!("../../../../configs/client-node.example.json")).unwrap();
        config["server"]["address"] = fixture.client.server.address.to_string().into();
        let path = root.join("isolated.json");
        fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        let mut settings = session::Settings::load(&fixture.relay).unwrap();
        settings.enable_tunnel();
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let fd = socket.as_raw_fd();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args(["--ignored", "--exact", "linux_namespace_socket_and_tun_ping", "--nocapture"]).env("MOSAIC_FIXTURE_FD", fd.to_string()).env("MOSAIC_FIXTURE_COOKIE", linux::cookie(&socket).unwrap().to_string()).env("MOSAIC_FIXTURE_CONFIG", &path);
        let parent = std::process::id() as libc::pid_t;
        unsafe { command.pre_exec(move || {
            linux::check(libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL))?;
            if libc::getppid() != parent { return Err(std::io::Error::other("fixture parent exited")); }
            linux::check(libc::unshare(libc::CLONE_NEWNET))?;
            linux::check(libc::fcntl(fd, libc::F_SETFD, 0))?;
            Ok(())
        }); }
        let mut child = command.spawn().unwrap();
        drop(socket);
        let outcome = timeout(Duration::from_secs(25), async {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            let _ready = session::accept(&connection, &settings).await.unwrap();
            let mut count = 0;
            loop {
                tokio::select! {
                    bytes = connection.read_datagram(), if count < 20 => {
                        let bytes = bytes.unwrap();
                        let (sequence, packet) = packet::decode(&bytes, Address::Source(ip())).unwrap();
                        assert_eq!(packet[9], 1);
                        assert_eq!(packet[20], 8);
                        let mut reply = packet.to_vec();
                        reply[12..16].copy_from_slice(&[10, 77, 0, 1]);
                        reply[16..20].copy_from_slice(&ip().octets());
                        reply[20] = 0;
                        reply[22..24].fill(0);
                        let mut sum = 0u32;
                        for chunk in reply[20..].chunks(2) { sum += u32::from(chunk[0]) * 256 + u32::from(*chunk.get(1).unwrap_or(&0)); }
                        while sum >> 16 != 0 { sum = (sum & 65535) + (sum >> 16); }
                        reply[22..24].copy_from_slice(&(!(sum as u16)).to_be_bytes());
                        checksum(&mut reply);
                        if count == 0 {
                            connection.send_datagram(vec![0; 20].into()).unwrap();
                            let mut spoof = reply.clone(); spoof[19] = 3; checksum(&mut spoof);
                            connection.send_datagram(packet::encode(sequence, &spoof, Address::Destination(Ipv4Addr::new(10, 77, 0, 3))).unwrap().into()).unwrap();
                        }
                        connection.send_datagram(packet::encode(sequence, &reply, Address::Destination(ip())).unwrap().into()).unwrap();
                        count += 1;
                    }
                    _ = tokio::time::sleep(Duration::from_millis(20)) => {
                        if let Some(status) = child.try_wait().unwrap() { return (status, count); }
                    }
                }
            }
        }).await;
        let _ = child.kill(); let _ = child.wait();
        let (status, count) = outcome.unwrap();
        assert!(status.success()); assert_eq!(count, 20);
        endpoint.close(0u32.into(), b"fixture complete");
    });
    let links_after = Command::new("ip")
        .args(["-j", "link", "show"])
        .output()
        .unwrap();
    assert_eq!(links_before.stdout, links_after.stdout);
}
