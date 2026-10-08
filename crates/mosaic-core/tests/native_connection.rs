mod support;
use anyhow::Result;
use mosaic_core::{
    config::{ClientConfig, Dns, Tunnel},
    native::{self, Platform, State, Status},
    pump::PacketIo,
    quic, session,
};
use std::{
    net::UdpSocket,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Notify, watch};

struct Network {
    ready: Notify,
    configuring: Notify,
    configured: AtomicBool,
    sockets: AtomicUsize,
    discards: AtomicUsize,
}

impl Network {
    fn new() -> Self {
        Self {
            ready: Notify::new(),
            configuring: Notify::new(),
            configured: AtomicBool::new(false),
            sockets: AtomicUsize::new(0),
            discards: AtomicUsize::new(0),
        }
    }
}

impl PacketIo for Network {
    async fn receive(&self, _: &mut [u8]) -> Result<usize> {
        std::future::pending().await
    }
    async fn send(&self, _: &[u8]) -> Result<()> {
        Ok(())
    }
}

impl Platform for Network {
    async fn protect(&self, _: &ClientConfig) -> Result<()> {
        Ok(())
    }
    async fn socket(&self, _: &ClientConfig) -> Result<UdpSocket> {
        self.sockets.fetch_add(1, Ordering::SeqCst);
        Ok(UdpSocket::bind("127.0.0.1:0")?)
    }
    async fn configure(&self, _: &ClientConfig) -> Result<()> {
        if !self.configured.load(Ordering::SeqCst) {
            self.configuring.notify_one();
            self.ready.notified().await;
            self.configured.store(true, Ordering::SeqCst);
        }
        Ok(())
    }
    async fn verify(&self) -> Result<()> {
        anyhow::ensure!(self.configured.load(Ordering::SeqCst), "routing not ready");
        Ok(())
    }
    async fn discard(&self) -> Result<()> {
        self.discards.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn native_config(config: &mut ClientConfig) {
    config.mode = "native_tun".into();
    config.network.change_host_network = true;
    config.tunnel = Some(Tunnel {
        name: "mosaic0".into(),
        address: "10.77.0.2/30".into(),
        peer: "10.77.0.1".parse().unwrap(),
        mtu: 1100,
        ipv6: "block".into(),
    });
    config.dns = Some(Dns {
        servers: vec!["1.1.1.1".parse().unwrap()],
    });
}

async fn wait_state(status: &mut watch::Receiver<Status>, state: State) {
    tokio::time::timeout(Duration::from_secs(8), async {
        while status.borrow().state != state {
            status.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
}

#[test]
fn retry_delays_are_jittered_and_capped() {
    for attempt in 0..100 {
        let low = native::retry_delay(attempt, 0);
        let high = native::retry_delay(attempt, u16::MAX);
        assert!(low < high && high <= Duration::from_secs(8));
        assert!(low >= Duration::from_millis(800));
    }
}

#[tokio::test]
async fn native_configuration_is_explicit_and_diagnostics_remain_compatible() {
    let mut fixture = support::Fixture::new();
    let (stop, server) = fixture.start();
    let (connection, _) = quic::connect_ready(&fixture.client).await.unwrap();
    quic::echo(&connection.connection, b"diagnostic compatibility")
        .await
        .unwrap();
    drop(connection);
    support::stop(stop, server).await;
    fixture.client.network.change_host_network = true;
    assert!(fixture.client.validate().is_err());
    native_config(&mut fixture.client);
    fixture.client.validate().unwrap();
    fixture.client.network.change_host_network = false;
    assert!(fixture.client.validate().is_err());
}

#[tokio::test]
async fn connection_waits_for_routes_and_reauthorizes_after_path_change() {
    let mut fixture = support::Fixture::new();
    let endpoint = quic::relay_endpoint(&fixture.relay).unwrap();
    fixture.client.server.address = endpoint.local_addr().unwrap();
    native_config(&mut fixture.client);
    let mut settings = session::Settings::load(&fixture.relay).unwrap();
    settings.enable_tunnel();
    let settings = Arc::new(settings);
    let sessions = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let observed = sessions.clone();
    let server = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        while let Some(incoming) = endpoint.accept().await {
            let settings = settings.clone();
            let observed = observed.clone();
            tasks.spawn(async move {
                let connection = incoming.await.unwrap();
                if let Ok(ready) = session::accept(&connection, &settings).await {
                    observed.lock().await.push(ready.session_id.clone());
                    connection.closed().await;
                    drop(ready);
                }
            });
        }
    });
    let network = Arc::new(Network::new());
    let worker_network = network.clone();
    let (status, mut current) = watch::channel(Status::new(State::Disconnected, "fixture"));
    let (stop, stopping) = watch::channel(false);
    let (path, changes) = watch::channel(0);
    let worker = tokio::spawn(async move {
        native::run(
            &fixture.client,
            worker_network.as_ref(),
            status,
            stopping,
            changes,
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(5), network.configuring.notified())
        .await
        .unwrap();
    assert_ne!(current.borrow().state, State::Connected);
    network.ready.notify_one();
    wait_state(&mut current, State::Connected).await;
    path.send_replace(1);
    wait_state(&mut current, State::Reconnecting).await;
    wait_state(&mut current, State::Connected).await;
    let sessions = sessions.lock().await;
    assert_eq!(sessions.len(), 2);
    assert_ne!(sessions[0], sessions[1]);
    assert!(network.discards.load(Ordering::SeqCst) >= 4);
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(1), worker)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    server.abort();
}

#[tokio::test]
async fn authorization_failure_stops_retries_without_configuring_routes() {
    let mut fixture = support::Fixture::new();
    let (stop_server, server) = fixture.start();
    native_config(&mut fixture.client);
    let directory = tempfile::TempDir::new().unwrap();
    let token = directory.path().join("wrong.token");
    std::fs::write(&token, "11".repeat(32)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    fixture.client.auth.token_file = token;
    let network = Network::new();
    let (status, current) = watch::channel(Status::new(State::Disconnected, "fixture"));
    let (_stop, stopping) = watch::channel(false);
    let (_path, changes) = watch::channel(0);
    let result = tokio::time::timeout(
        Duration::from_secs(6),
        native::run(&fixture.client, &network, status, stopping, changes),
    )
    .await
    .unwrap();
    assert!(result.is_err());
    assert_eq!(current.borrow().state, State::Failed);
    assert_eq!(network.sockets.load(Ordering::SeqCst), 1);
    assert!(!network.configured.load(Ordering::SeqCst));
    support::stop(stop_server, server).await;
}

#[tokio::test]
async fn disconnect_cancels_an_unresponsive_relay() {
    let mut fixture = support::Fixture::new();
    let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
    fixture.client.server.address = silent.local_addr().unwrap();
    native_config(&mut fixture.client);
    let network = Arc::new(Network::new());
    let worker_network = network.clone();
    let (status, _) = watch::channel(Status::new(State::Disconnected, "fixture"));
    let (stop, stopping) = watch::channel(false);
    let (_path, changes) = watch::channel(0);
    let worker = tokio::spawn(async move {
        native::run(
            &fixture.client,
            worker_network.as_ref(),
            status,
            stopping,
            changes,
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_millis(500), worker)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(!network.configured.load(Ordering::SeqCst));
}

fn tunnel_server(
    config: &mosaic_core::config::RelayConfig,
    sessions: Arc<tokio::sync::Mutex<Vec<String>>>,
) -> (quinn::Endpoint, tokio::task::JoinHandle<()>) {
    let endpoint = quic::relay_endpoint(config).unwrap();
    let listener = endpoint.clone();
    let mut settings = session::Settings::load(config).unwrap();
    settings.enable_tunnel();
    let settings = Arc::new(settings);
    let worker = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        while let Some(incoming) = listener.accept().await {
            let settings = settings.clone();
            let sessions = sessions.clone();
            tasks.spawn(async move {
                if let Ok(connection) = incoming.await
                    && let Ok(ready) = session::accept(&connection, &settings).await
                {
                    sessions.lock().await.push(ready.session_id.clone());
                    connection.closed().await;
                    drop(ready);
                }
            });
        }
    });
    (endpoint, worker)
}

#[tokio::test]
async fn three_twenty_second_outages_recover_with_fresh_authorization() {
    let mut fixture = support::Fixture::new();
    let sessions = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let (mut endpoint, mut server) = tunnel_server(&fixture.relay, sessions.clone());
    fixture.relay.listen = endpoint.local_addr().unwrap();
    fixture.client.server.address = fixture.relay.listen;
    native_config(&mut fixture.client);
    let network = Arc::new(Network::new());
    network.configured.store(true, Ordering::SeqCst);
    let worker_network = network.clone();
    let config = fixture.client.clone();
    let (status, mut current) = watch::channel(Status::new(State::Disconnected, "fixture"));
    let (stop, stopping) = watch::channel(false);
    let (_path, changes) = watch::channel(0);
    let worker = tokio::spawn(async move {
        native::run(&config, worker_network.as_ref(), status, stopping, changes).await
    });
    wait_state(&mut current, State::Connected).await;
    for _ in 0..3 {
        endpoint.close(0u32.into(), b"echo relay shutdown");
        server.abort();
        let _ = server.await;
        drop(endpoint);
        wait_state(&mut current, State::Reconnecting).await;
        tokio::time::sleep(Duration::from_secs(20)).await;
        assert_ne!(current.borrow().state, State::Connected);
        (endpoint, server) = tunnel_server(&fixture.relay, sessions.clone());
        tokio::time::timeout(Duration::from_secs(45), async {
            while current.borrow().state != State::Connected {
                current.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
    }
    let sessions = sessions.lock().await;
    assert_eq!(sessions.len(), 4);
    assert_eq!(
        sessions
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len(),
        4
    );
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(1), worker)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    endpoint.close(0u32.into(), b"fixture complete");
    server.abort();
}
