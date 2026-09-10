use crate::profile::{Profile, private_file};
#[cfg(target_os = "linux")]
use anyhow::Context;
use anyhow::{Result, ensure};
use mosaic_core::native::{self, Platform, State, Status};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::watch,
    task::JoinHandle,
};

#[cfg(target_os = "linux")]
use crate::linux::Network;
#[cfg(target_os = "windows")]
use crate::windows::Network;

#[derive(Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Import { profile: String },
    Connect,
    Disconnect,
    Status,
}

pub async fn read<T: AsyncRead + Unpin>(stream: &mut T) -> Result<Vec<u8>> {
    let length = stream.read_u32().await? as usize;
    ensure!(length > 0 && length <= 196608, "invalid local request size");
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}

pub async fn write<T: AsyncWrite + Unpin>(stream: &mut T, bytes: &[u8]) -> Result<()> {
    ensure!(bytes.len() <= 196608, "local response exceeds limit");
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(bytes).await?;
    stream.flush().await?;
    Ok(())
}

struct Active {
    network: Arc<Network>,
    stop: watch::Sender<bool>,
    worker: JoinHandle<()>,
    monitor: JoinHandle<()>,
    _directory: tempfile::TempDir,
}

pub struct Service {
    root: PathBuf,
    status: watch::Sender<Status>,
    active: Option<Active>,
}

impl Service {
    pub fn new(root: &Path) -> Self {
        let (status, _) =
            watch::channel(Status::new(State::Disconnected, "Mosaic is disconnected"));
        Self {
            root: root.into(),
            status,
            active: None,
        }
    }

    pub async fn recover(&mut self) -> Result<()> {
        if self.root.join("connected").exists() {
            self.connect(true).await?;
        }
        Ok(())
    }

    async fn connect(&mut self, recovering: bool) -> Result<()> {
        ensure!(
            self.active.is_none(),
            "Mosaic is already active; disconnect before connecting again"
        );
        let profile = Profile::load(&self.root.join("profile.mosaic"))?;
        self.clean_session(&profile)?;
        let directory = tempfile::Builder::new()
            .prefix("session-")
            .tempdir_in(&self.root)?;
        private_file(
            &self.root.join("session-directory"),
            directory.path().file_name().unwrap().as_encoded_bytes(),
        )?;
        let config = profile.install(directory.path())?;
        if !recovering {
            private_file(&self.root.join("connected"), b"Mosaic connection intent\n")?;
        }
        let network = match Network::create(&config, recovering) {
            Ok(network) => Arc::new(network),
            Err(_) => {
                self.status.send_replace(Status::new(State::Failed, "Native setup failed; protection may remain active. Disconnect to recover owned state"));
                return Err(anyhow::anyhow!("native setup failed"));
            }
        };
        network.protect(&config).await?;
        let (stop, stopping) = watch::channel(false);
        let (path, changes) = watch::channel(0);
        let status = self.status.clone();
        let worker_network = network.clone();
        self.status.send_replace(Status::new(
            State::Connecting,
            "Preparing protected networking",
        ));
        let worker = tokio::spawn(async move {
            if native::run(
                &config,
                worker_network.as_ref(),
                status.clone(),
                stopping,
                changes,
            )
            .await
            .is_err()
            {
                status.send_replace(Status::new(
                    State::Failed,
                    "Connection failed; traffic protection is retained until explicit disconnect",
                ));
            }
        });
        let watched = network.clone();
        let monitor = tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                if watched.changed().unwrap_or(true) {
                    path.send_modify(|value| *value = value.wrapping_add(1));
                }
            }
        });
        self.active = Some(Active {
            network,
            stop,
            worker,
            monitor,
            _directory: directory,
        });
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<()> {
        if let Some(active) = self.active.take() {
            active.stop.send_replace(true);
            active.monitor.abort();
            let _ = active.monitor.await;
            let _ = active.worker.await;
            if let Err(error) = active.network.cleanup() {
                self.status.send_replace(Status::new(State::Failed, "Cleanup conflict; protection is retained. Resolve the owned-state conflict before disconnecting again"));
                return Err(error);
            }
        } else if self.root.join("connected").exists() {
            let profile = Profile::load(&self.root.join("profile.mosaic"))?;
            let directory = tempfile::Builder::new()
                .prefix("recovery-")
                .tempdir_in(&self.root)?;
            let config = profile.install(directory.path())?;
            Network::recover_cleanup(&config)?;
        }
        if self.root.join("connected").exists() {
            std::fs::remove_file(self.root.join("connected"))?;
        }
        if self.root.join("session-directory").exists() {
            self.clean_session(&Profile::load(&self.root.join("profile.mosaic"))?)?;
        }
        self.status.send_replace(Status::new(
            State::Disconnected,
            "Owned routing, DNS and protection were removed",
        ));
        Ok(())
    }

    fn clean_session(&self, profile: &Profile) -> Result<()> {
        let record = self.root.join("session-directory");
        if !record.exists() {
            return Ok(());
        }
        let name = String::from_utf8(mosaic_core::config::read_bounded(&record, 128, true)?)?;
        ensure!(
            name.starts_with("session-")
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'),
            "session ownership record is invalid"
        );
        let directory = self.root.join(&name);
        if directory.exists() {
            ensure!(
                std::fs::symlink_metadata(&directory)?.file_type().is_dir(),
                "session directory ownership changed"
            );
            for (name, expected) in [
                ("relay.crt", profile.certificate.as_bytes()),
                ("client.token", profile.token.as_bytes()),
            ] {
                let file = directory.join(name);
                if file.exists() {
                    ensure!(
                        mosaic_core::config::read_bounded(&file, 32768, true)? == expected,
                        "session credentials changed externally"
                    );
                    std::fs::remove_file(file)?;
                }
            }
            std::fs::remove_dir(directory)?;
        }
        std::fs::remove_file(record)?;
        Ok(())
    }

    pub async fn handle(&mut self, request: Request) -> Status {
        let result = match request {
            Request::Status => return self.status.borrow().clone(),
            Request::Connect => self.connect(false).await,
            Request::Disconnect => self.disconnect().await,
            Request::Import { profile } => self.import(profile.as_bytes()),
        };
        if result.is_err() {
            return Status::new(
                State::Failed,
                "Request failed; verify configuration, installation permissions and owned network state. Existing protection is retained",
            );
        }
        self.status.borrow().clone()
    }

    fn import(&self, bytes: &[u8]) -> Result<()> {
        ensure!(
            self.active.is_none() && !self.root.join("connected").exists(),
            "disconnect before importing configuration"
        );
        Profile::read(bytes)?;
        let mut file = tempfile::NamedTempFile::new_in(&self.root)?;
        use std::io::Write;
        file.write_all(bytes)?;
        file.as_file().sync_all()?;
        file.persist(self.root.join("profile.mosaic"))
            .map_err(|_| anyhow::anyhow!("cannot save private configuration"))?;
        self.status.send_replace(Status::new(
            State::Disconnected,
            "Private configuration imported",
        ));
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub async fn serve() -> Result<()> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "run through the installed system service"
    );
    let root = Path::new("/var/lib/mosaic");
    let uid: u32 = std::fs::read_to_string(root.join("owner"))?
        .trim()
        .parse()?;
    let runtime = Path::new("/run/mosaic");
    std::fs::create_dir_all(runtime)?;
    std::fs::set_permissions(runtime, std::fs::Permissions::from_mode(0o755))?;
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(runtime.join("owner.lock"))?;
    use std::os::fd::AsRawFd;
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "another Mosaic service owns networking"
    );
    let socket = runtime.join("control.sock");
    if let Ok(meta) = std::fs::symlink_metadata(&socket) {
        ensure!(
            meta.file_type().is_socket(),
            "local control path is occupied"
        );
        std::fs::remove_file(&socket)?;
    }
    let listener = tokio::net::UnixListener::bind(&socket)?;
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
    let path = std::ffi::CString::new(socket.as_os_str().as_encoded_bytes())?;
    ensure!(
        unsafe { libc::chown(path.as_ptr(), uid, 0) } == 0,
        "cannot restrict local control ownership"
    );
    let mut service = Service::new(root);
    let recovery = service.recover().await;
    if recovery.is_err() {
        service.status.send_replace(Status::new(
            State::Failed,
            "Interrupted connection setup requires explicit disconnect and recovery",
        ));
    }
    if let Some(address) = std::env::var_os("NOTIFY_SOCKET") {
        let notification = std::os::unix::net::UnixDatagram::unbound()?;
        notification.connect(address)?;
        notification.send(b"READY=1")?;
    }
    loop {
        let (mut stream, _) = listener.accept().await?;
        let peer = stream.peer_cred()?;
        if peer.uid() != uid && peer.uid() != 0 {
            continue;
        }
        let response =
            tokio::time::timeout(std::time::Duration::from_secs(5), read(&mut stream)).await;
        let status = match response {
            Ok(Ok(bytes)) => match serde_json::from_slice::<Request>(&bytes) {
                Ok(request) => service.handle(request).await,
                Err(_) => Status::new(State::Failed, "Invalid local request"),
            },
            _ => Status::new(
                State::Failed,
                "Local request exceeded its limit or deadline",
            ),
        };
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            write(&mut stream, &serde_json::to_vec(&status)?),
        )
        .await;
    }
}

#[cfg(target_os = "linux")]
pub async fn request(request: Request) -> Result<Status> {
    let mut stream = tokio::net::UnixStream::connect("/run/mosaic/control.sock")
        .await
        .context("Mosaic service is not installed or this user is not authorized")?;
    write(&mut stream, &serde_json::to_vec(&request)?).await?;
    let bytes =
        tokio::time::timeout(std::time::Duration::from_secs(30), read(&mut stream)).await??;
    Ok(serde_json::from_slice(&bytes)?)
}
