use anyhow::{Context, Result, ensure};
use mosaic_core::{config::ClientConfig, native::Platform, pump::PacketIo, tun::Tun};
use serde_json::Value;
use std::{
    io::Write,
    net::UdpSocket,
    os::fd::AsRawFd,
    process::{Command, Stdio},
    sync::Mutex,
    time::{Duration, Instant},
};

pub const MARK: u32 = 0x4d4f;
pub const TABLE: &str = "19791";
const RULE: &str = "10990";
const EXEMPT: &str = "mosaic_exempt";

const UNIT: &str = "[Unit]\nDescription=Mosaic native VPN\nWants=network-pre.target\nBefore=network-pre.target\nAfter=systemd-resolved.service\nRequires=systemd-resolved.service\n\n[Service]\nType=notify\nExecStart=/usr/local/lib/mosaic/mosaic-service\nRestart=on-failure\nRestartSec=1\nRuntimeDirectory=mosaic\nRuntimeDirectoryMode=0755\nStateDirectory=mosaic\nStateDirectoryMode=0700\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nReadWritePaths=/var/lib/mosaic /run/mosaic\nCapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER\nMemoryMax=256M\nLimitNOFILE=1024\n\n[Install]\nWantedBy=multi-user.target\n";

pub fn setup(user: Option<u32>) -> Result<()> {
    use std::{os::unix::fs::PermissionsExt, path::Path};
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "setup requires installation approval through sudo"
    );
    let uid = user
        .or_else(|| std::env::var("SUDO_UID").ok()?.parse().ok())
        .context("specify the ordinary user's numeric UID during setup")?;
    ensure!(
        uid != 0 && unsafe { !libc::getpwuid(uid).is_null() },
        "setup requires an existing ordinary user"
    );
    let root = Path::new("/var/lib/mosaic");
    let binaries = Path::new("/usr/local/lib/mosaic");
    let unit = Path::new("/etc/systemd/system/mosaic.service");
    let client = std::env::current_exe()?;
    let service = client
        .parent()
        .context("package directory unavailable")?
        .join("mosaic-service");
    ensure!(
        service.is_file(),
        "keep the compiled service beside the client during installation"
    );
    command(
        "/usr/bin/systemctl",
        &["is-active", "systemd-resolved"],
        None,
    )?;
    ensure!(
        !root.join("connected").exists(),
        "disconnect before installing or upgrading Mosaic"
    );
    if root.exists() {
        ensure!(
            std::fs::read_to_string(root.join("owner"))?.trim() == uid.to_string(),
            "installation owner differs; preserve the existing installation"
        );
    } else {
        ensure!(
            !binaries.exists() && !unit.exists(),
            "installation paths are occupied without owned state"
        );
        std::fs::create_dir(root)?;
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
        crate::profile::private_file(&root.join("owner"), uid.to_string().as_bytes())?;
    }
    if unit.exists() {
        ensure!(
            std::fs::read_to_string(unit)? == UNIT,
            "service definition changed externally"
        );
        command("/usr/bin/systemctl", &["stop", "mosaic.service"], None)?;
    }
    let record = root.join("installation.json");
    let previous: Value = if record.exists() {
        serde_json::from_slice(&mosaic_core::config::read_bounded(&record, 8192, true)?)?
    } else {
        serde_json::json!({})
    };
    let mut files = serde_json::Map::new();
    for (source, name) in [(&client, "mosaic-client"), (&service, "mosaic-service")] {
        let destination = binaries.join(name);
        let wanted = binary_hash(source)?;
        let mut allowed = vec![wanted.clone()];
        if destination.exists() {
            let actual = binary_hash(&destination)?;
            ensure!(
                previous[name]
                    .as_array()
                    .is_some_and(|hashes| hashes.iter().any(|hash| hash == &actual)),
                "installed binary changed externally; preserve it and inspect the installation"
            );
            allowed.push(actual);
        }
        files.insert(name.into(), serde_json::json!(allowed));
    }
    let mut journal = tempfile::NamedTempFile::new_in(root)?;
    journal.write_all(&serde_json::to_vec(&files)?)?;
    journal.as_file().sync_all()?;
    journal
        .persist(record)
        .map_err(|_| anyhow::anyhow!("cannot save installation ownership"))?;
    if !binaries.exists() {
        std::fs::create_dir(binaries)?;
    }
    std::fs::set_permissions(binaries, std::fs::Permissions::from_mode(0o755))?;
    for (source, name) in [(&client, "mosaic-client"), (&service, "mosaic-service")] {
        let mut file = tempfile::NamedTempFile::new_in(binaries)?;
        std::io::copy(&mut std::fs::File::open(source)?, &mut file)?;
        file.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o755))?;
        file.as_file().sync_all()?;
        file.persist(binaries.join(name))
            .map_err(|_| anyhow::anyhow!("cannot install native component"))?;
    }
    if !unit.exists() {
        crate::profile::private_file(unit, UNIT.as_bytes())?;
    }
    std::fs::set_permissions(unit, std::fs::Permissions::from_mode(0o644))?;
    command("/usr/bin/systemctl", &["daemon-reload"], None)?;
    command(
        "/usr/bin/systemctl",
        &["enable", "--now", "mosaic.service"],
        None,
    )?;
    Ok(())
}

fn binary_hash(path: &std::path::Path) -> Result<String> {
    ensure!(
        std::fs::symlink_metadata(path)?.file_type().is_file(),
        "installed binary ownership changed"
    );
    Ok(mosaic_core::session::hex(
        ring::digest::digest(&ring::digest::SHA256, &std::fs::read(path)?).as_ref(),
    ))
}

pub fn uninstall() -> Result<()> {
    use std::path::Path;
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "uninstall requires installation approval through sudo"
    );
    let root = Path::new("/var/lib/mosaic");
    ensure!(
        !root.join("connected").exists(),
        "disconnect before uninstalling Mosaic"
    );
    let unit = Path::new("/etc/systemd/system/mosaic.service");
    ensure!(
        std::fs::read_to_string(unit)? == UNIT,
        "service definition was changed externally; inspect it before removal"
    );
    command(
        "/usr/bin/systemctl",
        &["disable", "--now", "mosaic.service"],
        None,
    )?;
    std::fs::remove_file(unit)?;
    command("/usr/bin/systemctl", &["daemon-reload"], None)?;
    let record: Value = serde_json::from_slice(&mosaic_core::config::read_bounded(
        &root.join("installation.json"),
        8192,
        true,
    )?)?;
    for name in ["mosaic-client", "mosaic-service"] {
        let path = Path::new("/usr/local/lib/mosaic").join(name);
        if path.exists() {
            let hash = binary_hash(&path)?;
            ensure!(
                record[name]
                    .as_array()
                    .is_some_and(|hashes| hashes.iter().any(|value| value == &hash)),
                "installed binary changed externally; preserve it before uninstalling"
            );
            std::fs::remove_file(path)?;
        }
    }
    std::fs::remove_dir("/usr/local/lib/mosaic")?;
    for name in ["owner", "profile.mosaic", "installation.json"] {
        let path = root.join(name);
        if path.is_file() {
            std::fs::remove_file(path)?;
        }
    }
    std::fs::remove_dir(root)?;
    Ok(())
}

pub fn command(program: &str, arguments: &[&str], input: Option<&[u8]>) -> Result<String> {
    let mut child = Command::new(program)
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("required native networking tool unavailable")?;
    if let Some(input) = input {
        child
            .stdin
            .take()
            .context("command input unavailable")?
            .write_all(input)?;
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait()? {
            ensure!(status.success(), "native networking command failed");
            let output = child.wait_with_output()?;
            ensure!(
                output.stdout.len() <= 65536,
                "network inventory exceeds limit"
            );
            return String::from_utf8(output.stdout).context("invalid network inventory");
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("native networking command timed out");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn ip(arguments: &[&str]) -> Result<String> {
    command("/usr/sbin/ip", arguments, None)
}
fn nft(arguments: &[&str], input: Option<&[u8]>) -> Result<String> {
    command("/usr/sbin/nft", arguments, input)
}
fn resolver(arguments: &[&str]) -> Result<String> {
    command("/usr/bin/resolvectl", arguments, None)
}

pub fn protection(config: &ClientConfig) -> String {
    let exempt = if config.exceptions.is_some() {
        format!("meta mark {MARK} accept; ")
    } else {
        String::new()
    };
    format!(
        "table inet mosaic_protect {{ comment \"Mosaic owned protection\"; chain output {{ type filter hook output priority 0; policy accept; oifname \"lo\" accept; meta mark {MARK} ip daddr {} udp dport {} accept; {exempt}oifname \"{}\" accept; ip daddr 255.255.255.255 udp sport 68 udp dport 67 accept; counter drop; }} }}\n",
        config.server.address.ip(),
        config.server.address.port(),
        config.tunnel.as_ref().unwrap().name
    )
}

pub fn exemptions(config: &ClientConfig, services: &[String]) -> Option<String> {
    let exceptions = config.exceptions.as_ref()?;
    let mut rules = format!(
        "meta mark {MARK} ip daddr {} udp dport {} accept; meta mark {MARK} meta mark set 0; ",
        config.server.address.ip(),
        config.server.address.port()
    );
    if exceptions.inbound_replies {
        rules.push_str(&format!(
            "meta mark 0 ct direction reply meta mark set {MARK}; "
        ));
    }
    for service in services {
        rules.push_str(&format!(
            "meta mark 0 socket cgroupv2 level 2 \"system.slice/{service}\" meta mark set {MARK}; "
        ));
    }
    Some(format!(
        "table inet {EXEMPT} {{ comment \"Mosaic owned exceptions\"; chain output {{ type route hook output priority mangle; policy accept; {rules}}} }}\n"
    ))
}

fn present_services(config: &ClientConfig) -> Vec<(String, u64)> {
    use std::os::unix::fs::MetadataExt;
    config
        .exceptions
        .iter()
        .flat_map(|exceptions| exceptions.services.iter())
        .filter_map(|service| {
            std::fs::metadata(format!("/sys/fs/cgroup/system.slice/{service}"))
                .ok()
                .filter(|metadata| metadata.is_dir())
                .map(|metadata| (service.clone(), metadata.ino()))
        })
        .collect()
}

fn table_present(name: &str) -> Result<bool> {
    let inventory: Value = serde_json::from_str(&nft(&["-j", "list", "tables"], None)?)?;
    Ok(inventory["nftables"]
        .as_array()
        .context("invalid firewall inventory")?
        .iter()
        .any(|entry| entry["table"]["family"] == "inet" && entry["table"]["name"] == name))
}

fn exempt_state() -> Result<Option<Value>> {
    if !table_present(EXEMPT)? {
        return Ok(None);
    }
    Ok(Some(normalized(serde_json::from_str(&nft(
        &["-j", "list", "table", "inet", EXEMPT],
        None,
    )?)?)))
}

type Exempt = (Vec<(String, u64)>, Option<Value>);

fn install_exemptions(config: &ClientConfig) -> Result<Exempt> {
    let mut attempt = 0;
    loop {
        let present = present_services(config);
        let names: Vec<String> = present.iter().map(|(name, _)| name.clone()).collect();
        let Some(definition) = exemptions(config, &names) else {
            return Ok((present, None));
        };
        let script = if table_present(EXEMPT)? {
            format!("delete table inet {EXEMPT}\n{definition}")
        } else {
            definition
        };
        let installed = nft(&["-c", "-f", "-"], Some(script.as_bytes()))
            .and_then(|_| nft(&["-f", "-"], Some(script.as_bytes())));
        match installed {
            Ok(_) => return Ok((present, exempt_state()?)),
            Err(_) if attempt == 0 && present != present_services(config) => attempt += 1,
            Err(error) => {
                return Err(error.context(
                    "cannot install traffic exceptions; service matching needs nftables socket cgroupv2 support on Linux 5.13 or newer",
                ));
            }
        }
    }
}

pub fn strict_reverse_path(all: Option<&str>, device: Option<&str>) -> bool {
    let value = |text: Option<&str>| text.and_then(|t| t.trim().parse::<u8>().ok()).unwrap_or(0);
    value(all).max(value(device)) == 1
}

fn reverse_path_setting(name: &str) -> Option<String> {
    std::fs::read_to_string(format!("/proc/sys/net/ipv4/conf/{name}/rp_filter")).ok()
}

fn underlying_device(config: &ClientConfig) -> Result<String> {
    let routes: Vec<Value> = serde_json::from_str(&ip(&[
        "-j",
        "-4",
        "route",
        "get",
        &config.server.address.ip().to_string(),
        "mark",
        &MARK.to_string(),
    ])?)?;
    Ok(routes
        .first()
        .and_then(|route| route["dev"].as_str())
        .context("no underlying relay path")?
        .to_string())
}

fn rules() -> Result<Vec<Value>> {
    Ok(serde_json::from_str(&ip(&["-j", "-4", "rule", "show"])?)?)
}

fn owned_rule(value: &Value, priority: &str, table: &str) -> bool {
    crate::ownership::rule(value, priority, table)
}

pub struct Network {
    tun: Tun,
    config: ClientConfig,
    configured: Mutex<bool>,
    protection: Mutex<Option<Value>>,
    path: Mutex<String>,
    exempt: Mutex<Exempt>,
}

fn normalized(mut value: Value) -> Value {
    fn clean(value: &mut Value) {
        match value {
            Value::Object(map) => {
                for key in ["handle", "packets", "bytes", "metainfo"] {
                    map.remove(key);
                }
                for value in map.values_mut() {
                    clean(value);
                }
            }
            Value::Array(values) => {
                values.retain(|value| value.get("metainfo").is_none());
                for value in values {
                    clean(value);
                }
            }
            _ => {}
        }
    }
    clean(&mut value);
    value
}

fn table_routes() -> Result<Vec<Value>> {
    let routes: Vec<Value> =
        serde_json::from_str(&ip(&["-j", "-4", "route", "show", "table", "all"])?)?;
    Ok(routes
        .into_iter()
        .filter(|route| {
            route["table"].as_u64() == TABLE.parse().ok() || route["table"].as_str() == Some(TABLE)
        })
        .collect())
}

fn owned_route(route: &Value, config: &ClientConfig) -> bool {
    route["dst"] == "default"
        && route["dev"] == config.tunnel.as_ref().unwrap().name
        && route["protocol"] == "static"
        && route.get("gateway").is_none()
        && route.get("multipath").is_none()
}

fn protection_state() -> Result<Option<Value>> {
    if !table_present("mosaic_protect")? {
        return Ok(None);
    }
    Ok(Some(normalized(serde_json::from_str(&nft(
        &["-j", "list", "table", "inet", "mosaic_protect"],
        None,
    )?)?)))
}

fn saved_protection() -> Result<Value> {
    Ok(serde_json::from_slice(&mosaic_core::config::read_bounded(
        std::path::Path::new("/var/lib/mosaic/protection.json"),
        65536,
        true,
    )?)?)
}

fn install_protection(config: &ClientConfig, recovering: bool) -> Result<Value> {
    if let Some(actual) = protection_state()? {
        ensure!(
            recovering && actual == saved_protection()?,
            "protection ownership conflict; existing filters are preserved"
        );
        return Ok(actual);
    }
    let script = protection(config);
    nft(&["-c", "-f", "-"], Some(script.as_bytes()))?;
    nft(&["-f", "-"], Some(script.as_bytes()))?;
    let actual = protection_state()?.context("protection was not installed")?;
    let mut snapshot = tempfile::NamedTempFile::new_in("/var/lib/mosaic")?;
    snapshot.write_all(&serde_json::to_vec(&actual)?)?;
    snapshot.as_file().sync_all()?;
    snapshot
        .persist("/var/lib/mosaic/protection.json")
        .map_err(|_| anyhow::anyhow!("cannot save protection ownership"))?;
    std::fs::File::open("/var/lib/mosaic")?.sync_all()?;
    Ok(actual)
}

impl Network {
    pub fn create(config: &ClientConfig, recovering: bool) -> Result<Self> {
        ensure!(
            unsafe { libc::geteuid() } == 0,
            "native service requires installed privileges"
        );
        config.validate()?;
        config.check_credentials()?;
        ensure!(config.mode == "native_tun", "native configuration required");
        resolver(&["status"])?;
        let existing = rules()?;
        {
            let (priority, table) = (RULE, TABLE);
            let matches: Vec<_> = existing
                .iter()
                .filter(|rule| rule["priority"].as_u64() == priority.parse().ok())
                .collect();
            ensure!(
                matches.is_empty()
                    || recovering && matches.len() == 1 && owned_rule(matches[0], priority, table),
                "routing policy conflict; preserve unrelated rules and resolve the Mosaic priority conflict"
            );
            if !recovering {
                ensure!(
                    table_routes()?.is_empty(),
                    "Mosaic route table is already in use"
                );
            }
        }
        let device = underlying_device(config)?;
        ensure!(
            !strict_reverse_path(
                reverse_path_setting("all").as_deref(),
                reverse_path_setting(&device).as_deref()
            ),
            "strict reverse-path filtering on the underlying interface would drop relay replies; use loose mode (2) or disable it"
        );
        ensure!(
            recovering || !table_present(EXEMPT)?,
            "traffic exception ownership conflict; existing filters are preserved"
        );
        ensure!(
            config
                .exceptions
                .as_ref()
                .is_none_or(|e| e.services.is_empty())
                || std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists(),
            "service traffic exceptions require the unified cgroup v2 hierarchy"
        );
        let exempt = install_exemptions(config)?;
        let protected = install_protection(config, recovering)?;
        let tun = Tun::create(config.tunnel.as_ref().unwrap())?;
        Ok(Self {
            tun,
            config: config.clone(),
            configured: Mutex::new(false),
            protection: Mutex::new(Some(protected)),
            path: Mutex::new(String::new()),
            exempt: Mutex::new(exempt),
        })
    }

    pub fn path(&self) -> Result<String> {
        let result = ip(&[
            "-j",
            "-4",
            "route",
            "get",
            &self.config.server.address.ip().to_string(),
            "mark",
            &MARK.to_string(),
        ])?;
        let routes: Vec<Value> = serde_json::from_str(&result)?;
        let route = routes.first().context("no underlying relay path")?;
        let device = route["dev"]
            .as_str()
            .context("missing underlying interface")?;
        ensure!(
            device != self.config.tunnel.as_ref().unwrap().name,
            "relay path recurses through Mosaic"
        );
        Ok(format!(
            "{}|{}",
            device,
            route["gateway"].as_str().unwrap_or("")
        ))
    }

    fn refresh_exceptions(&self) -> Result<()> {
        if self.config.exceptions.is_none() {
            return Ok(());
        }
        let present = present_services(&self.config);
        let mut exempt = self.exempt.lock().unwrap();
        if exempt.0 != present || !table_present(EXEMPT)? {
            *exempt = install_exemptions(&self.config)?;
            return Ok(());
        }
        ensure!(
            exempt_state()? == exempt.1,
            "Mosaic traffic exceptions changed"
        );
        Ok(())
    }

    pub fn changed(&self) -> Result<bool> {
        Ok(self.path()? != *self.path.lock().unwrap())
    }

    pub fn cleanup(&self) -> Result<()> {
        Self::recover_cleanup(&self.config)
    }

    pub fn recover_cleanup(config: &ClientConfig) -> Result<()> {
        let actual = protection_state()?;
        if let Some(actual) = actual.as_ref() {
            ensure!(
                *actual == saved_protection()?,
                "protection changed externally; inspect the Mosaic table before recovery"
            );
        }
        let existing = rules()?;
        let matches: Vec<_> = existing
            .iter()
            .filter(|rule| rule["priority"].as_u64() == RULE.parse().ok())
            .collect();
        ensure!(
            matches.is_empty() || matches.len() == 1 && owned_rule(matches[0], RULE, TABLE),
            "routing ownership changed; inspect Mosaic rules before recovery"
        );
        let routes = table_routes()?;
        ensure!(
            routes.iter().all(|route| owned_route(route, config)),
            "Mosaic route table changed externally"
        );
        if !matches.is_empty() {
            ip(&["-4", "rule", "del", "pref", RULE])?;
        }
        if !routes.is_empty() {
            ip(&[
                "-4",
                "route",
                "del",
                "table",
                TABLE,
                "default",
                "dev",
                &config.tunnel.as_ref().unwrap().name,
                "proto",
                "static",
            ])?;
        }
        if actual.is_some() {
            nft(&["delete", "table", "inet", "mosaic_protect"], None)?;
        }
        let snapshot = std::path::Path::new("/var/lib/mosaic/protection.json");
        if snapshot.exists() {
            std::fs::remove_file(snapshot)?;
        }
        if table_present(EXEMPT)? {
            nft(&["delete", "table", "inet", EXEMPT], None)?;
        }
        Ok(())
    }
}

impl PacketIo for Network {
    async fn receive(&self, bytes: &mut [u8]) -> Result<usize> {
        self.tun.receive(bytes).await
    }
    async fn send(&self, bytes: &[u8]) -> Result<()> {
        self.tun.send(bytes).await
    }
}

impl Platform for Network {
    async fn protect(&self, config: &ClientConfig) -> Result<()> {
        let _ = config;
        ensure!(
            protection_state()? == *self.protection.lock().unwrap(),
            "Mosaic traffic protection changed"
        );
        Ok(())
    }

    async fn socket(&self, _: &ClientConfig) -> Result<UdpSocket> {
        let path = self
            .path()
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::NetworkUnreachable))?;
        let interface = path.split('|').next().unwrap();
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        let mark = MARK;
        ensure!(
            unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    (&mark as *const u32).cast(),
                    4,
                )
            } == 0,
            "cannot protect relay socket"
        );
        let device = std::ffi::CString::new(interface)?;
        ensure!(
            unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_BINDTODEVICE,
                    device.as_ptr().cast(),
                    device.as_bytes_with_nul().len() as _,
                )
            } == 0,
            "cannot bind relay socket to the underlying path"
        );
        socket.set_nonblocking(true)?;
        *self.path.lock().unwrap() = path;
        Ok(socket)
    }

    async fn configure(&self, config: &ClientConfig) -> Result<()> {
        if *self.configured.lock().unwrap() {
            return Ok(());
        }
        let tun = &config.tunnel.as_ref().unwrap().name;
        ensure!(
            table_routes()?
                .iter()
                .all(|route| owned_route(route, config)),
            "Mosaic route table changed externally"
        );
        ip(&[
            "-4", "route", "replace", "table", TABLE, "default", "dev", tun, "proto", "static",
        ])?;
        let existing = rules()?;
        if !existing.iter().any(|rule| owned_rule(rule, RULE, TABLE)) {
            ip(&[
                "-4",
                "rule",
                "add",
                "pref",
                RULE,
                "not",
                "fwmark",
                &MARK.to_string(),
                "lookup",
                TABLE,
            ])?;
        }
        resolver(&["dns", tun, "1.1.1.1"])?;
        resolver(&["domain", tun, "~."])?;
        resolver(&["default-route", tun, "yes"])?;
        *self.configured.lock().unwrap() = true;
        Ok(())
    }

    async fn verify(&self) -> Result<()> {
        ensure!(
            rules()?.iter().any(|rule| owned_rule(rule, RULE, TABLE)),
            "Mosaic route rule disappeared"
        );
        self.refresh_exceptions()?;
        let actual: Value = serde_json::from_str(&nft(
            &["-j", "list", "table", "inet", "mosaic_protect"],
            None,
        )?)?;
        ensure!(
            Some(normalized(actual)) == *self.protection.lock().unwrap(),
            "Mosaic traffic protection changed"
        );
        let tun = &self.config.tunnel.as_ref().unwrap().name;
        let routes: Vec<Value> =
            serde_json::from_str(&ip(&["-j", "-4", "route", "get", "1.1.1.1"])?)?;
        ensure!(
            routes.first().is_some_and(|route| route["dev"] == *tun),
            "system DNS route is not using Mosaic"
        );
        ensure!(
            resolver(&["dns", tun])?.split_whitespace().last() == Some("1.1.1.1"),
            "Mosaic resolver was changed"
        );
        ensure!(
            resolver(&["domain", tun])?.split_whitespace().last() == Some("~."),
            "Mosaic resolver routing was changed"
        );
        Ok(())
    }

    async fn discard(&self) -> Result<()> {
        self.refresh_exceptions()?;
        for _ in 0..256 {
            let mut packet = [0; 1101];
            if tokio::time::timeout(Duration::from_millis(1), self.tun.receive(&mut packet))
                .await
                .is_err()
            {
                break;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(exceptions: Option<mosaic_core::config::Exceptions>) -> ClientConfig {
        let mut config: ClientConfig =
            serde_json::from_str(include_str!("../../../configs/client-native.example.json"))
                .unwrap();
        config.exceptions = exceptions;
        config
    }

    #[test]
    fn protection_without_exceptions_keeps_the_narrow_relay_rule() {
        let text = protection(&config(None));
        assert!(text.contains(&format!(
            "meta mark {MARK} ip daddr 203.0.113.10 udp dport 443 accept"
        )));
        assert!(!text.contains(&format!("meta mark {MARK} accept")));
        assert!(text.ends_with("counter drop; } }\n"));
        assert!(exemptions(&config(None), &[]).is_none());
    }

    #[test]
    fn exceptions_mark_inbound_replies_and_named_services_only() {
        let exceptions = mosaic_core::config::Exceptions {
            inbound_replies: true,
            services: vec!["xray.service".into()],
        };
        let config = config(Some(exceptions));
        assert!(protection(&config).contains(&format!("meta mark {MARK} accept; oifname")));
        let text = exemptions(&config, &["xray.service".into()]).unwrap();
        assert!(text.contains("type route hook output priority mangle"));
        assert!(text.contains(&format!(
            "meta mark 0 ct direction reply meta mark set {MARK}"
        )));
        assert!(text.contains(&format!(
            "meta mark 0 socket cgroupv2 level 2 \"system.slice/xray.service\" meta mark set {MARK}"
        )));
        let strip = text
            .find(&format!("meta mark {MARK} meta mark set 0"))
            .unwrap();
        let relay = text
            .find(&format!(
                "meta mark {MARK} ip daddr 203.0.113.10 udp dport 443 accept"
            ))
            .unwrap();
        assert!(relay < strip && strip < text.find("ct direction").unwrap());
        let without_service = exemptions(&config, &[]).unwrap();
        assert!(!without_service.contains("cgroupv2"));
    }

    #[test]
    fn strict_reverse_path_filtering_is_detected() {
        assert!(strict_reverse_path(Some("1\n"), Some("0\n")));
        assert!(strict_reverse_path(Some("0\n"), Some("1\n")));
        assert!(!strict_reverse_path(Some("2\n"), Some("1\n")));
        assert!(!strict_reverse_path(Some("0\n"), Some("2\n")));
        assert!(!strict_reverse_path(None, None));
    }
}
