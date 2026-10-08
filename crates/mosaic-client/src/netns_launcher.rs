#[cfg(target_os = "linux")]
use anyhow::Context;
use anyhow::{Result, ensure};
use mosaic_core::{
    config::ClientConfig,
    report::{Report, Status},
};
use std::{path::Path, process::ExitCode};

pub struct Options<'a> {
    pub config: &'a Path,
    pub policy: &'a Path,
    pub baseline: &'a Path,
    pub guard: &'a Path,
    pub output: Option<&'a Path>,
    pub dedicated_host: bool,
}

pub fn launch(options: Options<'_>) -> ExitCode {
    let mut report = Report::new("isolated-tun");
    report.check_level = 5;
    let result = ClientConfig::load(options.config).and_then(|c| {
        c.check_credentials()?;
        ensure!(
            c.mode == "isolated_tun",
            "isolated TUN configuration required"
        );
        #[cfg(target_os = "linux")]
        return linux::launch(&c, &options, &mut report);
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (
                &options.policy,
                &options.baseline,
                &options.guard,
                options.dedicated_host,
            );
            report.add(
                "isolation.platform",
                Status::Blocked,
                "isolated TUN requires the inventoried Linux node",
            );
            Ok(())
        }
    });
    if let Err(error) = result {
        report.add("isolation.run", Status::Fail, &error.to_string());
    }
    if report.emit(options.output).is_err() {
        return ExitCode::from(1);
    }
    ExitCode::from(report.exit_code())
}

pub fn cleanup(namespace: &str, output: Option<&Path>) -> ExitCode {
    let mut report = Report::new("isolation-cleanup");
    report.check_level = 5;
    #[cfg(target_os = "linux")]
    match linux::cleanup(namespace, false) {
        Ok(()) => report.add(
            "isolation.cleanup",
            Status::Pass,
            "recorded worker, socket and namespace released",
        ),
        Err(error) => report.add("isolation.cleanup", Status::Fail, &error.to_string()),
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = namespace;
        report.add(
            "isolation.platform",
            Status::Blocked,
            "namespace cleanup requires Linux",
        );
    }
    if report.emit(output).is_err() {
        return ExitCode::from(1);
    }
    ExitCode::from(report.exit_code())
}

pub fn execute(namespace: &str, args: &[std::ffi::OsString]) -> ExitCode {
    #[cfg(target_os = "linux")]
    {
        if let Err(error) = linux::execute(namespace, args) {
            eprintln!("FAIL isolation.execute: {error}");
        }
        ExitCode::from(1)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (namespace, args);
        eprintln!("BLOCKED isolation.platform: namespace applications require Linux");
        ExitCode::from(2)
    }
}

pub fn worker(config: &Path, fd: i32, cookie: u64, uid: u32) -> Result<()> {
    #[cfg(target_os = "linux")]
    return linux::worker(config, fd, cookie, uid);
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (config, fd, cookie, uid);
        anyhow::bail!("isolated worker requires Linux")
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use mosaic_core::{
        linux::{self, check},
        namespace,
        packet::Address,
        pump, quic, session,
        tun::Tun,
    };
    use serde::{Deserialize, Serialize};
    use std::{
        ffi::CString,
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        net::UdpSocket,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{
                fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
                process::CommandExt,
            },
        },
        path::PathBuf,
        process::{Child, Command, Stdio},
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicU64, Ordering},
        },
        time::{Duration, Instant},
    };

    static STOP: AtomicBool = AtomicBool::new(false);
    extern "C" fn stop(_: i32) {
        STOP.store(true, Ordering::Relaxed);
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Process {
        pid: u32,
        start: String,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Owner {
        namespace: String,
        parent: Process,
        worker: Option<Process>,
        namespace_inode: Option<u64>,
        #[serde(default)]
        worker_mount_inode: Option<u64>,
        mount_inode: Option<u64>,
        socket_inode: Option<u64>,
        socket_port: Option<u16>,
        socket_uid: u32,
        socket_cookie: Option<u64>,
    }

    fn process(pid: u32) -> Result<Process> {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
        let start = stat
            .rsplit_once(") ")
            .context("invalid process identity")?
            .1
            .split_whitespace()
            .nth(19)
            .context("missing process identity")?
            .to_owned();
        Ok(Process { pid, start })
    }

    fn alive(p: &Process) -> bool {
        process(p.pid).is_ok_and(|current| current.start == p.start)
    }

    fn paths(namespace: &str) -> Result<(PathBuf, PathBuf)> {
        ensure!(
            namespace.starts_with("mosaic-")
                && namespace.len() <= 15
                && namespace
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "invalid namespace name"
        );
        Ok((
            PathBuf::from(format!("/run/{namespace}")),
            PathBuf::from(format!("/run/netns/{namespace}")),
        ))
    }

    fn root() -> Result<()> {
        ensure!(
            unsafe { libc::geteuid() } == 0,
            "namespace setup requires root on Linux"
        );
        Ok(())
    }

    fn save(directory: &Path, owner: &Owner) -> Result<()> {
        let next = directory.join("owner.next");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&next)?;
        file.write_all(&serde_json::to_vec(owner)?)?;
        file.sync_all()?;
        fs::rename(next, directory.join("owner.json"))?;
        File::open(directory)?.sync_all()?;
        Ok(())
    }

    fn guard_command(options: &Options<'_>, action: &str, directory: &Path) -> Command {
        let mut command = Command::new("python3");
        command
            .arg(options.guard)
            .arg(action)
            .arg("--policy")
            .arg(options.policy)
            .arg("--baseline")
            .arg(options.baseline)
            .arg("--directory")
            .arg(directory)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }

    fn wait_command(mut child: Child, seconds: u64) -> Result<()> {
        let start = Instant::now();
        loop {
            if let Some(status) = child.try_wait()? {
                ensure!(
                    status.success(),
                    "VPN preservation guard failed; inspect its private report"
                );
                return Ok(());
            }
            if start.elapsed() >= Duration::from_secs(seconds) {
                let _ = child.kill();
                let _ = child.wait();
                anyhow::bail!("preservation guard deadline");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    pub fn launch(c: &ClientConfig, options: &Options<'_>, report: &mut Report) -> Result<()> {
        root()?;
        ensure!(
            c.server.address.is_ipv4()
                && !matches!(c.server.address.ip(), std::net::IpAddr::V4(ip) if ip.is_documentation()),
            "real IPv4 relay address required"
        );
        let isolation = c.isolation.as_ref().context("missing isolation settings")?;
        let tunnel = c.tunnel.as_ref().context("missing TUN settings")?;
        let policy: serde_json::Value = serde_json::from_slice(
            &mosaic_core::config::read_bounded(options.policy, 65536, false)?,
        )?;
        let uid = u32::try_from(
            policy["test_uid"]
                .as_u64()
                .context("missing transport UID")?,
        )?;
        ensure!(
            uid > 0
                && policy["namespace"].as_str() == Some(&isolation.namespace)
                && policy["relay_ip"].as_str() == Some(&c.server.address.ip().to_string()),
            "policy must match namespace, non-root UID and relay"
        );
        let ip: std::net::Ipv4Addr = tunnel
            .address
            .split_once('/')
            .context("invalid tunnel address")?
            .0
            .parse()?;
        let subnet = format!("{}/30", std::net::Ipv4Addr::from(u32::from(ip) & !3));
        ensure!(
            policy["tunnel_subnet"].as_str() == Some(&subnet),
            "policy subnet must match TUN"
        );
        let (directory, mount) = paths(&isolation.namespace)?;
        ensure!(
            !mount.try_exists()? && !directory.try_exists()?,
            "refusing existing namespace or ownership directory"
        );
        fs::DirBuilder::new().mode(0o700).create(&directory)?;
        let mut owner = Owner {
            namespace: isolation.namespace.clone(),
            parent: process(std::process::id())?,
            worker: None,
            namespace_inode: None,
            worker_mount_inode: None,
            mount_inode: None,
            socket_inode: None,
            socket_port: None,
            socket_uid: uid,
            socket_cookie: None,
        };
        save(&directory, &owner)?;
        if options.dedicated_host {
            let relay = match c.server.address.ip() {
                std::net::IpAddr::V4(ip) => u32::from(ip),
                std::net::IpAddr::V6(_) => 0,
            };
            ensure!(
                mosaic_core::proxy::local_networks()
                    .iter()
                    .any(|(address, _)| *address == relay),
                "dedicated host mode requires the relay to run on this host"
            );
        }
        let mut child: Option<Child> = None;
        let mut guard: Option<Child> = None;
        let mut socket = None;
        let result = (|| {
            if options.dedicated_host {
                report.add(
                    "isolation.baseline",
                    Status::Pass,
                    "dedicated relay host: the shared-node VPN guard does not apply; namespace isolation checks remain and preservation must be monitored separately",
                );
            } else {
                wait_command(guard_command(options, "verify", &directory).spawn()?, 20)?;
                report.add(
                    "isolation.baseline",
                    Status::Pass,
                    "fresh five-minute VPN baseline and current controls verified",
                );
            }
            let setup = Instant::now();
            let user = unsafe { libc::getpwuid(uid) };
            ensure!(!user.is_null(), "transport UID has no account");
            let gid = unsafe { (*user).pw_gid };
            let original_gid = unsafe { libc::getegid() };
            check(unsafe { libc::setgroups(0, std::ptr::null()) })?;
            check(unsafe { libc::setegid(gid) })?;
            check(unsafe { libc::seteuid(uid) })?;
            let opened = UdpSocket::bind("0.0.0.0:0");
            check(unsafe { libc::seteuid(0) })?;
            check(unsafe { libc::setegid(original_gid) })?;
            let udp = opened?;
            udp.set_nonblocking(true)?;
            let cookie = linux::cookie(&udp)?;
            let fd = udp.as_raw_fd();
            owner.socket_inode = Some(fs::metadata(format!("/proc/self/fd/{fd}"))?.ino());
            owner.socket_port = Some(udp.local_addr()?.port());
            owner.socket_cookie = Some(cookie);
            socket = Some(udp);
            save(&directory, &owner)?;
            let mut command = Command::new(std::env::current_exe()?);
            command
                .arg("isolated-worker")
                .arg("-c")
                .arg(fs::canonicalize(options.config)?)
                .arg("--fd")
                .arg(fd.to_string())
                .arg("--cookie")
                .arg(cookie.to_string())
                .arg("--uid")
                .arg(uid.to_string())
                .stdin(Stdio::piped());
            let parent = std::process::id() as libc::pid_t;
            unsafe {
                command.pre_exec(move || {
                    check(libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL))?;
                    if libc::getppid() != parent {
                        return Err(std::io::Error::other("launcher exited"));
                    }
                    check(libc::unshare(libc::CLONE_NEWNET | libc::CLONE_NEWNS))?;
                    check(libc::fcntl(fd, libc::F_SETFD, 0))?;
                    Ok(())
                });
            }
            let worker = command.spawn()?;
            let pid = worker.id();
            child = Some(worker);
            owner.worker = Some(process(pid)?);
            owner.namespace_inode = Some(fs::metadata(format!("/proc/{pid}/ns/net"))?.ino());
            owner.worker_mount_inode = Some(fs::metadata(format!("/proc/{pid}/ns/mnt"))?.ino());
            save(&directory, &owner)?;
            let netns = Path::new("/run/netns");
            if !netns.exists() {
                fs::create_dir(netns)?;
            }
            let metadata = fs::symlink_metadata(netns)?;
            ensure!(
                metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
                "unsafe namespace directory"
            );
            let target = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(mount.with_extension("setup"))?;
            owner.mount_inode = Some(target.metadata()?.ino());
            save(&directory, &owner)?;
            let staged = CString::new(
                mount
                    .with_extension("setup")
                    .to_str()
                    .context("invalid namespace path")?,
            )?;
            let named = CString::new(mount.to_str().context("invalid namespace path")?)?;
            check(unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    libc::AT_FDCWD,
                    staged.as_ptr(),
                    libc::AT_FDCWD,
                    named.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            } as i32)?;
            let source = CString::new(format!("/proc/{pid}/ns/net"))?;
            let destination = CString::new(mount.to_str().context("invalid namespace path")?)?;
            check(unsafe {
                libc::mount(
                    source.as_ptr(),
                    destination.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null(),
                )
            })?;
            ensure!(
                setup.elapsed() < Duration::from_secs(5),
                "namespace setup exceeded control sampling interval"
            );
            drop(socket.take());
            if !options.dedicated_host {
                guard = Some(guard_command(options, "watch", &directory).spawn()?);
            }
            let start = Instant::now();
            while guard.is_some() && !directory.join("guard.ready").exists() {
                ensure!(
                    guard
                        .as_mut()
                        .context("missing guard")?
                        .try_wait()?
                        .is_none(),
                    "preservation guard rejected namespace setup"
                );
                ensure!(
                    start.elapsed() < Duration::from_secs(10),
                    "preservation guard readiness deadline"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
            unsafe {
                libc::signal(libc::SIGINT, stop as *const () as libc::sighandler_t);
                libc::signal(libc::SIGTERM, stop as *const () as libc::sighandler_t);
            }
            child
                .as_mut()
                .context("missing worker")?
                .stdin
                .take()
                .context("missing worker startup pipe")?
                .write_all(b"start\n")?;
            loop {
                if STOP.load(Ordering::Relaxed) {
                    return Ok(());
                }
                if let Some(monitor) = guard.as_mut() {
                    ensure!(
                        monitor.try_wait()?.is_none(),
                        "VPN preservation failed; stopping Mosaic worker"
                    );
                    ensure!(
                        fs::metadata(directory.join("guard.ready"))?
                            .modified()?
                            .elapsed()?
                            .as_secs()
                            < 10,
                        "VPN preservation guard stopped sampling"
                    );
                }
                if let Some(status) = child.as_mut().context("missing worker")?.try_wait()? {
                    ensure!(status.success(), "isolated worker failed");
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        })();
        if let Some(mut worker) = child {
            if matches!(worker.try_wait(), Ok(None)) {
                unsafe {
                    libc::kill(worker.id() as libc::pid_t, libc::SIGTERM);
                }
                let start = Instant::now();
                while matches!(worker.try_wait(), Ok(None))
                    && start.elapsed() < Duration::from_secs(2)
                {
                    std::thread::sleep(Duration::from_millis(20));
                }
                let _ = worker.kill();
            }
            let _ = worker.wait();
        }
        drop(socket);
        if let Some(mut monitor) = guard {
            let _ = monitor.kill();
            let _ = monitor.wait();
        }
        let removed = cleanup(&isolation.namespace, true);
        if removed.is_ok() {
            report.add(
                "isolation.cleanup",
                Status::Pass,
                "owned worker and UDP socket stopped; owned namespace removed",
            );
            if !options.dedicated_host {
                wait_command(guard_command(options, "verify", &directory).spawn()?, 20)?;
                report.add(
                    "isolation.preservation",
                    Status::Pass,
                    "host and VPN controls verified after cleanup",
                );
            }
        }
        result?;
        removed?;
        Ok(())
    }

    pub fn cleanup(namespace: &str, allow_parent: bool) -> Result<()> {
        root()?;
        let (directory, mount) = paths(namespace)?;
        let meta = fs::symlink_metadata(&directory)?;
        ensure!(
            meta.is_dir() && meta.uid() == 0 && meta.mode() & 0o077 == 0,
            "unsafe ownership directory"
        );
        let owner: Owner = serde_json::from_slice(&mosaic_core::config::read_bounded(
            &directory.join("owner.json"),
            16384,
            true,
        )?)?;
        ensure!(
            owner.namespace == namespace && (allow_parent || !alive(&owner.parent)),
            "launcher is active or ownership mismatch"
        );
        if let Some(inode) = owner.namespace_inode {
            for item in fs::read_dir("/proc")? {
                let item = item?;
                let Ok(pid) = item.file_name().to_string_lossy().parse::<u32>() else {
                    continue;
                };
                if fs::metadata(item.path().join("ns/net")).is_ok_and(|m| m.ino() == inode) {
                    ensure!(
                        owner
                            .worker
                            .as_ref()
                            .is_some_and(|p| p.pid == pid && alive(p)),
                        "namespace has an unrecognized process; refusing cleanup"
                    );
                }
            }
        }
        if let Some(worker) = &owner.worker
            && alive(worker)
        {
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, worker.pid, 0) } as i32;
            check(fd)?;
            let handle = unsafe { File::from_raw_fd(fd) };
            ensure!(alive(worker), "worker identity changed");
            check(unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    handle.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            } as i32)?;
            let start = Instant::now();
            while fs::metadata(format!("/proc/{}/ns/net", worker.pid)).is_ok() {
                ensure!(
                    start.elapsed() < Duration::from_secs(5),
                    "worker cleanup deadline"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        if mount.try_exists()? {
            let meta = fs::symlink_metadata(&mount)?;
            ensure!(!meta.file_type().is_symlink(), "namespace mount changed");
            if Some(meta.ino()) == owner.namespace_inode {
                let name = CString::new(mount.to_str().context("invalid namespace path")?)?;
                check(unsafe { libc::umount2(name.as_ptr(), 0) })?;
            }
            ensure!(
                Some(fs::symlink_metadata(&mount)?.ino()) == owner.mount_inode,
                "namespace file ownership changed"
            );
            fs::remove_file(&mount)?;
        }
        let staged = mount.with_extension("setup");
        if staged.try_exists()? {
            ensure!(
                Some(fs::symlink_metadata(&staged)?.ino()) == owner.mount_inode,
                "namespace setup file ownership changed"
            );
            fs::remove_file(staged)?;
        }
        for name in [
            "owner.json",
            "owner.next",
            "guard.ready",
            "guard.next",
            "guard.json",
            "tunnel.ready",
            "tunnel.next",
        ] {
            let path = directory.join(name);
            if path.try_exists()? {
                fs::remove_file(path)?;
            }
        }
        fs::remove_dir(directory)?;
        Ok(())
    }

    pub fn execute(name: &str, args: &[std::ffi::OsString]) -> Result<()> {
        root()?;
        ensure!(!args.is_empty(), "application command required");
        let (directory, mount) = paths(name)?;
        let metadata = fs::symlink_metadata(&directory)?;
        ensure!(
            metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o077 == 0,
            "unsafe ownership directory"
        );
        let owner: Owner = serde_json::from_slice(&mosaic_core::config::read_bounded(
            &directory.join("owner.json"),
            16384,
            true,
        )?)?;
        let worker = owner.worker.as_ref().context("missing worker")?;
        ensure!(
            owner.namespace == name && alive(&owner.parent) && alive(worker),
            "namespace owner is inactive"
        );
        ensure!(
            fs::read(directory.join("tunnel.ready"))? == b"ready\n",
            "namespace routing is not ready"
        );
        ensure!(
            fs::metadata(directory.join("guard.ready"))?
                .modified()?
                .elapsed()?
                < Duration::from_secs(10),
            "VPN preservation guard is not current"
        );
        let net = File::open(format!("/proc/{}/ns/net", worker.pid))?;
        let mounts = File::open(format!("/proc/{}/ns/mnt", worker.pid))?;
        ensure!(
            Some(net.metadata()?.ino()) == owner.namespace_inode
                && Some(fs::metadata(mount)?.ino()) == owner.namespace_inode,
            "network namespace changed"
        );
        ensure!(
            Some(mounts.metadata()?.ino()) == owner.worker_mount_inode
                && mounts.metadata()?.ino() != fs::metadata("/proc/self/ns/mnt")?.ino(),
            "private resolver mount namespace changed"
        );
        ensure!(
            alive(worker) && owner.socket_uid > 0,
            "worker identity changed"
        );
        let user = unsafe { libc::getpwuid(owner.socket_uid) };
        ensure!(!user.is_null(), "test UID has no account");
        let gid = unsafe { (*user).pw_gid };
        check(unsafe { libc::setns(net.as_raw_fd(), libc::CLONE_NEWNET) })?;
        check(unsafe { libc::setns(mounts.as_raw_fd(), libc::CLONE_NEWNS) })?;
        ensure!(
            fs::read("/etc/resolv.conf")? == namespace::RESOLVER.as_bytes(),
            "private resolver changed"
        );
        check(unsafe { libc::setgroups(0, std::ptr::null()) })?;
        check(unsafe { libc::setgid(gid) })?;
        check(unsafe { libc::setuid(owner.socket_uid) })?;
        check(unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) })?;
        let error = Command::new(&args[0])
            .args(&args[1..])
            .env("MOSAIC_NAMESPACE", name)
            .env("MOSAIC_NAMESPACE_INODE", net.metadata()?.ino().to_string())
            .env_remove("LOCALDOMAIN")
            .env_remove("RES_OPTIONS")
            .env_remove("HOSTALIASES")
            .exec();
        Err(error).context("cannot execute namespace application")
    }

    pub fn worker(config: &Path, fd: i32, expected_cookie: u64, uid: u32) -> Result<()> {
        root()?;
        let parent = unsafe { libc::getppid() };
        ensure!(fd >= 3 && uid > 0, "invalid inherited socket settings");
        let mut start = [0; 6];
        std::io::stdin().read_exact(&mut start)?;
        ensure!(&start == b"start\n", "launcher startup rejected");
        let socket = unsafe { UdpSocket::from_raw_fd(fd) };
        check(unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) })?;
        let local = UdpSocket::bind("0.0.0.0:0")?;
        ensure!(
            linux::cookie(&socket)? == expected_cookie && linux::cookie(&local)? != expected_cookie,
            "inherited UDP socket namespace proof failed"
        );
        drop(local);
        linux::command("ip", &["link", "set", "lo", "up"])?;
        let c = ClientConfig::load(config)?;
        c.check_credentials()?;
        namespace::private_dns()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let connect = |socket: UdpSocket| {
            let c = &c;
            async move {
                let client = quic::connect_socket(c, socket)
                    .await
                    .context("inherited UDP QUIC connection failed")?;
                let ready = session::authorize_tunnel(&client.connection, c)
                    .await
                    .context("tunnel authorization failed")?;
                Ok::<_, anyhow::Error>((client, ready))
            }
        };
        runtime.block_on(async {
            let (mut client, mut ready) = connect(socket.try_clone()?).await?;
            let config = c.tunnel.as_ref().context("missing TUN settings")?;
            let tun = Tun::create(config)?;
            namespace::default_route(&config.name)?;
            let directory = paths(&c.isolation.as_ref().context("missing isolation settings")?.namespace)?.0;
            let mut ready_file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(directory.join("tunnel.next"))?;
            ready_file.write_all(b"ready\n")?;
            ready_file.sync_all()?;
            drop(ready_file);
            fs::rename(directory.join("tunnel.next"), directory.join("tunnel.ready"))?;
            let address = config.address.split_once('/').context("invalid TUN address")?.0.parse()?;
            check(unsafe { libc::setgroups(0, std::ptr::null()) })?;
            let user = unsafe { libc::getpwuid(uid) };
            ensure!(!user.is_null(), "transport UID has no account");
            let gid = unsafe { (*user).pw_gid };
            check(unsafe { libc::setgid(gid) })?;
            check(unsafe { libc::setuid(uid) })?;
            check(unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) })?;
            ensure!(unsafe { libc::getppid() } == parent, "launcher exited during privilege drop");
            check(unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) })?;
            let mut report = Report::new("isolated-tun-ready");
            report.check_level = 5;
            report.add("isolation.socket", Status::Pass, "authenticated QUIC over inherited host-namespace UDP socket; namespace cookies differ; worker privileges dropped");
            report.add("isolation.tun", Status::Pass, "exclusive IPv4 TUN created after Ready with MTU 1100; no host route, DNS, firewall or forwarding changes");
            report.add("isolation.routing", Status::Pass, "namespace default route uses TUN; private resolver uses only 1.1.1.1; use isolated-exec for application DNS");
            report.emit(None)?;
            let counters = Arc::new(pump::Counters::default());
            let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            let max_mbps = Some(c.test_limits.as_ref().context("missing rate limits")?.max_mbps);
            let mut sessions = 1u64;
            let result = 'outer: loop {
                let work = pump::run(&client.connection, &tun, pump::Options { outbound: Address::Source(address), inbound: Address::Destination(address), queue_packets: c.limits.queue_packets, max_mbps }, counters.clone());
                let outcome = tokio::select! {
                    result = work => result,
                    _ = terminate.recv() => break Ok(()),
                    _ = tokio::signal::ctrl_c() => break Ok(()),
                };
                if let Err(error) = outcome && !mosaic_core::native::retryable(&error) {
                    break Err(error);
                }
                drop(ready);
                drop(client);
                eprintln!("tunnel reconnecting; namespace and TUN retained");
                let mut attempt = 0u32;
                loop {
                    let mut random = [0u8; 2];
                    let filled = unsafe { libc::getrandom(random.as_mut_ptr().cast(), 2, 0) };
                    ensure!(filled == 2, "retry randomness unavailable");
                    let delay = mosaic_core::native::retry_delay(attempt, u16::from_ne_bytes(random));
                    attempt = attempt.saturating_add(1);
                    tokio::select! {
                        _ = tokio::time::sleep(delay) => {},
                        _ = terminate.recv() => break 'outer Ok(()),
                        _ = tokio::signal::ctrl_c() => break 'outer Ok(()),
                    }
                    match connect(socket.try_clone()?).await {
                        Ok((next, lease)) => {
                            client = next;
                            ready = lease;
                            sessions += 1;
                            eprintln!("tunnel reconnected; new authenticated session {sessions}");
                            break;
                        }
                        Err(error) if !mosaic_core::native::retryable(&error) => break 'outer Err(error),
                        Err(_) => {}
                    }
                }
            };
            let count = |value: &AtomicU64| value.load(Ordering::Relaxed);
            eprintln!("tunnel sessions={sessions} sent={} received={} rejected={} dropped={}", count(&counters.sent), count(&counters.received), count(&counters.rejected), count(&counters.dropped));
            result
        })
    }
}
