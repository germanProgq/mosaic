use crate::system::{root, run};
use anyhow::{Context, Result, ensure};
use mosaic_core::config::RelayConfig;
use serde_json::{Value, json};
use std::{
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

const BINARIES: &str = "/usr/local/lib/mosaic-relay";
const SETTINGS: &str = "/etc/mosaic-relay";
const STATE: &str = "/var/lib/mosaic-relay";
const UNIT_PATH: &str = "/etc/systemd/system/mosaic-relay.service";
const SERVICE: &str = "mosaic-relay.service";

pub const UNIT: &str = "[Unit]\nDescription=Mosaic relay\nWants=network-online.target\nAfter=network-online.target docker.service nftables.service\nStartLimitIntervalSec=0\n\n[Service]\nType=simple\nExecStart=/usr/local/lib/mosaic-relay/mosaic-relay -c /etc/mosaic-relay/relay.json --tunnel --forwarding --proxy\nRestart=on-failure\nRestartSec=5\nStateDirectory=mosaic-relay\nStateDirectoryMode=0700\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nProtectKernelModules=yes\nProtectKernelLogs=yes\nProtectControlGroups=yes\nProtectClock=yes\nRestrictNamespaces=yes\nRestrictRealtime=yes\nRestrictSUIDSGID=yes\nLockPersonality=yes\nRestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX\nDevicePolicy=closed\nDeviceAllow=/dev/net/tun rw\nCapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE\nMemoryMax=512M\nLimitNOFILE=4096\n\n[Install]\nWantedBy=multi-user.target\n";

fn hash(path: &Path) -> Result<String> {
    ensure!(
        std::fs::symlink_metadata(path)?.file_type().is_file(),
        "installed file ownership changed"
    );
    Ok(mosaic_core::session::hex(
        ring_digest(&std::fs::read(path)?).as_slice(),
    ))
}

fn ring_digest(bytes: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .to_vec()
}

fn write_file(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let directory = path.parent().context("invalid installation path")?;
    let mut file = tempfile::NamedTempFile::new_in(directory)?;
    file.write_all(bytes)?;
    file.as_file()
        .set_permissions(std::fs::Permissions::from_mode(mode))?;
    file.as_file().sync_all()?;
    file.persist(path)
        .map_err(|_| anyhow::anyhow!("cannot install relay file"))?;
    Ok(())
}

fn private_directory(path: &Path, mode: u32) -> Result<()> {
    if !path.exists() {
        std::fs::create_dir(path)?;
    }
    ensure!(
        std::fs::symlink_metadata(path)?.is_dir(),
        "installation directory ownership changed"
    );
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn record() -> Result<Option<Value>> {
    let path = Path::new(STATE).join("installation.json");
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_slice(
        &mosaic_core::config::read_bounded(&path, 65536, true)?,
    )?))
}

fn installed_files() -> Vec<PathBuf> {
    vec![
        Path::new(BINARIES).join("mosaic-relay"),
        Path::new(SETTINGS).join("relay.json"),
        Path::new(SETTINGS).join("secrets/relay.crt"),
        Path::new(SETTINGS).join("secrets/relay.key"),
        Path::new(SETTINGS).join("secrets/client.token"),
        PathBuf::from(UNIT_PATH),
    ]
}

fn verify_owned(record: &Value) -> Result<()> {
    for path in installed_files() {
        let key = path.to_string_lossy();
        if path.exists() {
            let actual = hash(&path)?;
            ensure!(
                record[key.as_ref()]
                    .as_array()
                    .is_some_and(|hashes| hashes.iter().any(|value| value == &actual)),
                "installed relay file changed externally; preserve it and inspect the installation"
            );
        }
    }
    Ok(())
}

pub fn installed_config(config: &RelayConfig) -> Result<Vec<u8>> {
    let mut installed = config.clone();
    installed.tls.cert = "secrets/relay.crt".into();
    installed.tls.key = "secrets/relay.key".into();
    installed.auth.token_file = "secrets/client.token".into();
    Ok(serde_json::to_vec_pretty(&installed)?)
}

pub fn setup(config_path: &Path) -> Result<()> {
    root()?;
    let config = RelayConfig::load(config_path)?;
    config.check_credentials()?;
    mosaic_core::config::tunnel(&config.tunnel)?;
    let previous = record()?;
    match &previous {
        Some(record) => verify_owned(record)?,
        None => ensure!(
            installed_files().iter().all(|path| !path.exists())
                && !Path::new(BINARIES).exists()
                && !Path::new(SETTINGS).exists(),
            "relay installation paths are occupied without owned state"
        ),
    }
    let sources: Vec<(PathBuf, Vec<u8>, u32)> = vec![
        (
            Path::new(BINARIES).join("mosaic-relay"),
            std::fs::read("/proc/self/exe")?,
            0o755,
        ),
        (
            Path::new(SETTINGS).join("relay.json"),
            installed_config(&config)?,
            0o600,
        ),
        (
            Path::new(SETTINGS).join("secrets/relay.crt"),
            mosaic_core::config::read_bounded(&config.tls.cert, 32768, false)?,
            0o600,
        ),
        (
            Path::new(SETTINGS).join("secrets/relay.key"),
            mosaic_core::config::read_bounded(&config.tls.key, 16384, true)?,
            0o600,
        ),
        (
            Path::new(SETTINGS).join("secrets/client.token"),
            mosaic_core::config::read_bounded(&config.auth.token_file, 66, true)?,
            0o600,
        ),
        (PathBuf::from(UNIT_PATH), UNIT.as_bytes().to_vec(), 0o644),
    ];
    let mut owned = serde_json::Map::new();
    for (path, bytes, _) in &sources {
        let key = path.to_string_lossy().to_string();
        let mut hashes = vec![json!(mosaic_core::session::hex(&ring_digest(bytes)))];
        if let Some(previous) = previous.as_ref().and_then(|r| r[&key].as_array()) {
            hashes.extend(previous.iter().cloned());
        }
        owned.insert(key, Value::Array(hashes));
    }
    let current: serde_json::Map<String, Value> = sources
        .iter()
        .map(|(path, bytes, _)| {
            (
                path.to_string_lossy().to_string(),
                json!([mosaic_core::session::hex(&ring_digest(bytes))]),
            )
        })
        .collect();
    private_directory(Path::new(STATE), 0o700)?;
    write_file(
        &Path::new(STATE).join("installation.json"),
        &serde_json::to_vec(&owned)?,
        0o600,
    )?;
    if previous.is_some() {
        run("systemctl", &["stop", SERVICE], None)?;
    }
    private_directory(Path::new(BINARIES), 0o755)?;
    private_directory(Path::new(SETTINGS), 0o700)?;
    private_directory(&Path::new(SETTINGS).join("secrets"), 0o700)?;
    for (path, bytes, mode) in &sources {
        write_file(path, bytes, *mode)?;
    }
    run("systemctl", &["daemon-reload"], None)?;
    run("systemctl", &["reset-failed", SERVICE], None).ok();
    run("systemctl", &["enable", "--now", SERVICE], None)?;
    std::thread::sleep(std::time::Duration::from_secs(4));
    let state = run(
        "systemctl",
        &["show", "--property=ActiveState,NRestarts", SERVICE],
        None,
    )?;
    ensure!(
        state.lines().any(|line| line == "ActiveState=active")
            && state.lines().any(|line| line == "NRestarts=0"),
        "relay service did not stay active; inspect its journal"
    );
    write_file(
        &Path::new(STATE).join("installation.json"),
        &serde_json::to_vec(&current)?,
        0o600,
    )?;
    Ok(())
}

pub fn uninstall() -> Result<()> {
    root()?;
    let record = record()?.context("no owned relay installation was found")?;
    verify_owned(&record)?;
    if Path::new(UNIT_PATH).exists() {
        run("systemctl", &["disable", "--now", SERVICE], None)?;
    }
    crate::forwarding::recover(Path::new(STATE))
        .context("relay forwarding cleanup did not finish; inspect the Mosaic firewall tables")?;
    for path in installed_files() {
        if path.exists() {
            std::fs::remove_file(path)?;
        }
    }
    run("systemctl", &["daemon-reload"], None)?;
    for directory in [
        Path::new(SETTINGS).join("secrets"),
        PathBuf::from(SETTINGS),
        PathBuf::from(BINARIES),
    ] {
        if directory.exists() {
            std::fs::remove_dir(&directory)
                .context("relay directory contains files Mosaic does not own")?;
        }
    }
    std::fs::remove_file(Path::new(STATE).join("installation.json"))?;
    std::fs::remove_dir(STATE).context("relay state directory contains unowned files")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_runs_the_installed_tunnel_with_forwarding() {
        assert!(UNIT.contains(
            "ExecStart=/usr/local/lib/mosaic-relay/mosaic-relay -c /etc/mosaic-relay/relay.json --tunnel --forwarding"
        ));
        assert!(UNIT.contains("Restart=on-failure"));
        assert!(UNIT.contains("NoNewPrivileges=yes"));
        assert!(!UNIT.contains("python"));
    }
}
