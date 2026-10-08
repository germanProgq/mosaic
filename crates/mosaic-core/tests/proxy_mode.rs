#[allow(dead_code)]
mod support;
use mosaic_core::{proxy, quic, session};
use std::time::Duration;
use tokio::sync::oneshot;

async fn relay(
    fixture: &mut support::Fixture,
    enabled: bool,
) -> (oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
    let endpoint = quic::relay_endpoint(&fixture.relay).unwrap();
    fixture.client.server.address = endpoint.local_addr().unwrap();
    let mut settings = session::Settings::load(&fixture.relay).unwrap();
    if enabled {
        settings.enable_proxy();
    }
    let (stop, stopped) = oneshot::channel::<()>();
    let task = tokio::spawn(quic::serve(endpoint, settings, async {
        let _ = stopped.await;
    }));
    (stop, task)
}

#[tokio::test]
async fn proxy_sessions_refuse_private_destinations_and_blocked_ports() {
    let mut fixture = support::Fixture::new();
    let (stop, task) = relay(&mut fixture, true).await;
    let client = quic::connect(&fixture.client).await.unwrap();
    session::authorize_proxy(&client.connection, &fixture.client)
        .await
        .unwrap();
    let limit = fixture.client.limits.max_control_bytes;
    for host in ["127.0.0.1", "10.0.0.1", "169.254.169.254", "localhost"] {
        let opened = tokio::time::timeout(
            Duration::from_secs(20),
            proxy::open_stream(&client.connection, host, 80, limit),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(opened.is_none(), "{host}");
    }
    assert!(
        proxy::open_stream(&client.connection, "example.com", 25, limit)
            .await
            .is_err()
    );
    assert!(client.connection.close_reason().is_none());
    drop(client);
    stop.send(()).unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn proxy_mode_is_refused_unless_enabled() {
    let mut fixture = support::Fixture::new();
    let (stop, task) = relay(&mut fixture, false).await;
    let client = quic::connect(&fixture.client).await.unwrap();
    assert!(
        session::authorize_proxy(&client.connection, &fixture.client)
            .await
            .is_err()
    );
    drop(client);
    stop.send(()).unwrap();
    task.await.unwrap();
}
