use crate::profile::Profile;
use anyhow::{Result, ensure};
use mosaic_core::{
    config::ClientConfig,
    frame,
    native::{self, Platform, State, Status},
    pump::PacketIo,
};
use std::{
    collections::HashMap,
    net::UdpSocket,
    os::fd::AsRawFd,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering},
    },
    thread::JoinHandle,
    time::Duration,
};
use tokio::sync::{Mutex as AsyncMutex, mpsc, watch};

struct Bridge {
    input: AsyncMutex<mpsc::Receiver<Vec<u8>>>,
    sender: mpsc::Sender<Vec<u8>>,
    output: Mutex<mpsc::Receiver<Vec<u8>>>,
    writer: mpsc::Sender<Vec<u8>>,
    status: watch::Sender<Status>,
    stop: watch::Sender<bool>,
    path: watch::Sender<u64>,
    socket_fd: AtomicI32,
    socket_ready: watch::Sender<i32>,
    network_pending: AtomicBool,
    network_ready: watch::Sender<i32>,
    configured: AtomicBool,
    settings: Vec<u8>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

fn bridges() -> &'static Mutex<HashMap<u64, Arc<Bridge>>> {
    static HANDLES: OnceLock<Mutex<HashMap<u64, Arc<Bridge>>>> = OnceLock::new();
    HANDLES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn get(handle: u64) -> Option<Arc<Bridge>> {
    bridges().lock().ok()?.get(&handle).cloned()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mosaic_validate_profile(bytes: *const u8, length: usize) -> i32 {
    if bytes.is_null() || length == 0 || length > 98304 {
        return 0;
    }
    Profile::read(unsafe { std::slice::from_raw_parts(bytes, length) }).is_ok() as i32
}

impl PacketIo for Bridge {
    async fn receive(&self, bytes: &mut [u8]) -> Result<usize> {
        let packet = self
            .input
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("packet reader stopped"))?;
        ensure!(packet.len() <= bytes.len(), "packet exceeds buffer");
        bytes[..packet.len()].copy_from_slice(&packet);
        Ok(packet.len())
    }

    async fn send(&self, bytes: &[u8]) -> Result<()> {
        ensure!(bytes.len() <= frame::MTU, "packet exceeds MTU");
        match self.writer.try_send(bytes.to_vec()) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
            Err(_) => Err(anyhow::anyhow!("packet writer stopped")),
        }
    }
}

struct PendingSocket<'a>(&'a AtomicI32);
impl Drop for PendingSocket<'_> {
    fn drop(&mut self) {
        self.0.store(-1, Ordering::Release);
    }
}

struct PendingNetwork<'a>(&'a AtomicBool);
impl Drop for PendingNetwork<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl Platform for Bridge {
    async fn protect(&self, _: &ClientConfig) -> Result<()> {
        Ok(())
    }

    async fn socket(&self, _: &ClientConfig) -> Result<UdpSocket> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_nonblocking(true)?;
        self.socket_ready.send_replace(0);
        let mut result = self.socket_ready.subscribe();
        self.socket_fd.store(socket.as_raw_fd(), Ordering::Release);
        let _pending = PendingSocket(&self.socket_fd);
        let ready = tokio::time::timeout(Duration::from_secs(5), result.changed()).await;
        self.socket_fd.store(-1, Ordering::Release);
        ready??;
        ensure!(*result.borrow() == 1, "underlying socket protection failed");
        Ok(socket)
    }

    async fn configure(&self, _: &ClientConfig) -> Result<()> {
        if self.configured.load(Ordering::Acquire) {
            return Ok(());
        }
        self.network_ready.send_replace(0);
        let mut result = self.network_ready.subscribe();
        self.network_pending.store(true, Ordering::Release);
        let _pending = PendingNetwork(&self.network_pending);
        let ready = tokio::time::timeout(Duration::from_secs(15), result.changed()).await;
        self.network_pending.store(false, Ordering::Release);
        ready??;
        ensure!(*result.borrow() == 1, "native routing or DNS setup failed");
        self.configured.store(true, Ordering::Release);
        Ok(())
    }

    async fn verify(&self) -> Result<()> {
        ensure!(
            self.configured.load(Ordering::Acquire),
            "native tunnel unavailable"
        );
        Ok(())
    }

    async fn discard(&self) -> Result<()> {
        let mut input = self.input.lock().await;
        while input.try_recv().is_ok() {}
        let mut output = self
            .output
            .lock()
            .map_err(|_| anyhow::anyhow!("packet queue unavailable"))?;
        while output.try_recv().is_ok() {}
        Ok(())
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mosaic_start(bytes: *const u8, length: usize) -> u64 {
    if bytes.is_null() || length == 0 || length > 98304 {
        return 0;
    }
    let bytes = unsafe { std::slice::from_raw_parts(bytes, length) };
    start(bytes, None)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mosaic_start_in(
    bytes: *const u8,
    length: usize,
    path: *const u8,
    path_length: usize,
) -> u64 {
    if bytes.is_null() || length == 0 || length > 98304 || path.is_null() || path_length > 4096 {
        return 0;
    }
    let Ok(path) = std::str::from_utf8(unsafe { std::slice::from_raw_parts(path, path_length) })
    else {
        return 0;
    };
    start(
        unsafe { std::slice::from_raw_parts(bytes, length) },
        Some(std::path::Path::new(path)),
    )
}

fn start(bytes: &[u8], path: Option<&std::path::Path>) -> u64 {
    let Ok(profile) = Profile::read(bytes) else {
        return 0;
    };
    if profile.config.exceptions.is_some() {
        return 0;
    }
    let mut builder = tempfile::Builder::new();
    builder.prefix("mosaic-");
    let directory = match path {
        Some(path) => builder.tempdir_in(path),
        None => builder.tempdir(),
    };
    let Ok(directory) = directory else {
        return 0;
    };
    let Ok(config) = profile.install(directory.path()) else {
        return 0;
    };
    let Some(tunnel) = config.tunnel.as_ref() else {
        return 0;
    };
    let settings = serde_json::to_vec(&serde_json::json!({
        "relay": config.server.address.ip().to_string(), "port": config.server.address.port(),
        "address": tunnel.address.split('/').next().unwrap(), "peer": tunnel.peer.to_string(),
        "mtu": tunnel.mtu, "dns": "1.1.1.1", "ipv6": "block"
    }))
    .unwrap();
    let (sender, input) = mpsc::channel(config.limits.queue_packets);
    let (writer, output) = mpsc::channel(config.limits.queue_packets);
    let (status, _) = watch::channel(Status::new(
        State::Connecting,
        "Waiting for protected native networking",
    ));
    let (stop, stopping) = watch::channel(false);
    let (path, changes) = watch::channel(0);
    let (socket_ready, _) = watch::channel(0);
    let (network_ready, _) = watch::channel(0);
    let bridge = Arc::new(Bridge {
        input: AsyncMutex::new(input),
        sender,
        output: Mutex::new(output),
        writer,
        status,
        stop,
        path,
        socket_fd: AtomicI32::new(-1),
        socket_ready,
        network_pending: AtomicBool::new(false),
        network_ready,
        configured: AtomicBool::new(false),
        settings,
        thread: Mutex::new(None),
    });
    let Ok(mut handles) = bridges().lock() else {
        return 0;
    };
    if !handles.is_empty() {
        return 0;
    }
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let handle = NEXT.fetch_add(1, Ordering::Relaxed);
    let worker = bridge.clone();
    let Ok(thread) = std::thread::Builder::new().name("mosaic-connection".into()).spawn(move || {
        let _directory = directory;
        match tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build() {
            Ok(runtime) => {
                if runtime.block_on(native::run(&config, worker.as_ref(), worker.status.clone(), stopping, changes)).is_err() {
                    worker.status.send_replace(Status::new(State::Failed, "Connection failed; disconnect explicitly or correct configuration before retrying"));
                }
            }
            Err(_) => { worker.status.send_replace(Status::new(State::Failed, "Cannot start the connection runtime")); }
        }
    }) else { return 0; };
    *bridge.thread.lock().unwrap() = Some(thread);
    handles.insert(handle, bridge);
    handle
}

#[unsafe(no_mangle)]
pub extern "C" fn mosaic_stop(handle: u64) {
    let Ok(mut entries) = bridges().lock() else {
        return;
    };
    if let Some(bridge) = entries.get(&handle).cloned() {
        bridge.stop.send_replace(true);
        if let Some(thread) = bridge
            .thread
            .lock()
            .ok()
            .and_then(|mut thread| thread.take())
        {
            let _ = thread.join();
        }
        entries.remove(&handle);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn mosaic_socket(handle: u64) -> i32 {
    get(handle).map_or(-1, |bridge| bridge.socket_fd.load(Ordering::Acquire))
}

#[unsafe(no_mangle)]
pub extern "C" fn mosaic_socket_ready(handle: u64, fd: i32, ready: i32) {
    if let Some(bridge) = get(handle)
        && fd >= 0
        && bridge.socket_fd.load(Ordering::Acquire) == fd
    {
        bridge
            .socket_ready
            .send_replace(if ready == 1 { 1 } else { -1 });
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn mosaic_needs_network(handle: u64) -> i32 {
    get(handle).is_some_and(|bridge| bridge.network_pending.load(Ordering::Acquire)) as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn mosaic_network_ready(handle: u64, ready: i32) {
    if let Some(bridge) = get(handle) {
        if ready != 1 {
            bridge.configured.store(false, Ordering::Release);
        }
        bridge
            .network_ready
            .send_replace(if ready == 1 { 1 } else { -1 });
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn mosaic_path_changed(handle: u64) {
    if let Some(bridge) = get(handle) {
        bridge
            .path
            .send_modify(|value| *value = value.wrapping_add(1));
    }
}

unsafe fn copy(bytes: &[u8], output: *mut u8, capacity: usize) -> i32 {
    if output.is_null() || bytes.len() > capacity {
        return -1;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len());
    }
    bytes.len() as i32
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mosaic_settings(handle: u64, output: *mut u8, capacity: usize) -> i32 {
    get(handle).map_or(-1, |bridge| unsafe {
        copy(&bridge.settings, output, capacity)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mosaic_status(handle: u64, output: *mut u8, capacity: usize) -> i32 {
    get(handle).map_or(-1, |bridge| unsafe {
        copy(
            &serde_json::to_vec(&*bridge.status.borrow()).unwrap(),
            output,
            capacity,
        )
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mosaic_write_packet(handle: u64, bytes: *const u8, length: usize) -> i32 {
    if bytes.is_null() || length == 0 || length > frame::MTU {
        return -1;
    }
    let Some(bridge) = get(handle) else {
        return -1;
    };
    if bridge.status.borrow().state != State::Connected {
        return 0;
    }
    let bytes = unsafe { std::slice::from_raw_parts(bytes, length) };
    match bridge.sender.try_send(bytes.to_vec()) {
        Ok(()) => 1,
        Err(mpsc::error::TrySendError::Full(_)) => 0,
        Err(_) => -1,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mosaic_read_packet(handle: u64, output: *mut u8, capacity: usize) -> i32 {
    let Some(bridge) = get(handle) else {
        return -1;
    };
    let Ok(mut packets) = bridge.output.lock() else {
        return -1;
    };
    match packets.try_recv() {
        Ok(packet) => unsafe { copy(&packet, output, capacity) },
        Err(mpsc::error::TryRecvError::Empty) => 0,
        Err(_) => -1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> Vec<u8> {
        let config: ClientConfig =
            serde_json::from_str(include_str!("../../../configs/client-native.example.json"))
                .unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["relay.example.net".into()]).unwrap();
        serde_json::to_vec(&Profile {
            config,
            certificate: cert.cert.pem(),
            token: "a5".repeat(32),
        })
        .unwrap()
    }

    #[test]
    fn private_profile_rejects_bad_input_and_never_overwrites() {
        let bytes = profile();
        Profile::read(&bytes).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["token"] = "private-secret-invalid".into();
        let error = Profile::read(&serde_json::to_vec(&value).unwrap())
            .err()
            .unwrap();
        assert!(!error.to_string().contains("private-secret-invalid"));
        assert!(Profile::read(&vec![b' '; 98305]).is_err());
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("client.mosaic");
        crate::profile::private_file(&path, &bytes).unwrap();
        assert!(crate::profile::private_file(&path, b"replacement").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let link = directory.path().join("linked.mosaic");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(Profile::load(&link).is_err());
    }

    #[test]
    fn native_handles_bound_queues_and_cancel_pending_socket_work() {
        let bytes = profile();
        let handle = start(&bytes, None);
        assert_ne!(handle, 0);
        assert_eq!(start(&bytes, None), 0);
        let bridge = get(handle).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while mosaic_socket(handle) < 0 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(mosaic_socket(handle) >= 0);
        bridge
            .status
            .send_replace(Status::new(State::Connected, "fixture"));
        let packet = [0u8; 1100];
        let config: ClientConfig =
            serde_json::from_str(include_str!("../../../configs/client-native.example.json"))
                .unwrap();
        let limit = config.limits.queue_packets as i32;
        let mut accepted = 0;
        for _ in 0..limit * 4 {
            accepted +=
                unsafe { mosaic_write_packet(handle, packet.as_ptr(), packet.len()) }.max(0);
        }
        assert!(accepted > 0 && accepted <= limit);
        assert_eq!(
            unsafe { mosaic_write_packet(handle, packet.as_ptr(), 1101) },
            -1
        );
        bridge.configured.store(true, Ordering::Release);
        mosaic_network_ready(handle, -1);
        assert!(!bridge.configured.load(Ordering::Acquire));
        let before = std::time::Instant::now();
        mosaic_stop(handle);
        assert!(before.elapsed() < Duration::from_secs(1));
        assert_eq!(bridge.socket_fd.load(Ordering::Acquire), -1);
        assert_eq!(mosaic_socket(handle), -1);
        assert_eq!(
            unsafe { mosaic_write_packet(handle, packet.as_ptr(), packet.len()) },
            -1
        );
    }
}
