use mosaic_core::{
    config::{ClientConfig, RelayConfig},
    quic,
};
use std::{fs, path::Path, time::Duration};
use tempfile::TempDir;
use tokio::{sync::oneshot, task::JoinHandle, time::timeout};

pub struct Fixture {
    _directory: TempDir,
    pub client: ClientConfig,
    pub relay: RelayConfig,
}
impl Fixture {
    pub fn new() -> Self {
        let directory = TempDir::new().unwrap();
        let root = directory.path();
        fs::create_dir(root.join("secrets")).unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["relay.example.net".into()]).unwrap();
        fs::write(root.join("secrets/relay.crt"), cert.cert.pem()).unwrap();
        fs::write(
            root.join("secrets/relay.key"),
            cert.signing_key.serialize_pem(),
        )
        .unwrap();
        fs::write(root.join("secrets/client.token"), "a5".repeat(32)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for name in ["relay.key", "client.token"] {
                fs::set_permissions(
                    root.join("secrets").join(name),
                    fs::Permissions::from_mode(0o600),
                )
                .unwrap();
            }
        }
        let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../configs");
        for name in ["client", "relay"] {
            fs::copy(
                examples.join(format!("{name}.example.json")),
                root.join(format!("{name}.json")),
            )
            .unwrap();
        }
        let client = ClientConfig::load(&root.join("client.json")).unwrap();
        let mut relay = RelayConfig::load(&root.join("relay.json")).unwrap();
        client.check_credentials().unwrap();
        relay.check_credentials().unwrap();
        relay.listen = "127.0.0.1:0".parse().unwrap();
        Self {
            _directory: directory,
            client,
            relay,
        }
    }
    pub fn start(&mut self) -> (oneshot::Sender<()>, JoinHandle<()>) {
        let endpoint = quic::relay_endpoint(&self.relay).unwrap();
        self.client.server.address = endpoint.local_addr().unwrap();
        let (tx, rx) = oneshot::channel();
        (
            tx,
            tokio::spawn(quic::serve(
                endpoint,
                mosaic_core::session::Settings::load(&self.relay).unwrap(),
                async {
                    let _ = rx.await;
                },
            )),
        )
    }
}
pub async fn stop(tx: oneshot::Sender<()>, handle: JoinHandle<()>) {
    tx.send(()).unwrap();
    timeout(Duration::from_secs(2), handle)
        .await
        .unwrap()
        .unwrap();
}
