use crate::{
    rules::{self, EGRESS, Plan, Target},
    system::run,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    net::Ipv4Addr,
    path::{Path, PathBuf},
};

const FORWARDING: &str = "/proc/sys/net/ipv4/ip_forward";
const STATE: &str = "forwarding.json";

#[derive(Serialize, Deserialize)]
struct State {
    tun: String,
    wan: String,
    client: Ipv4Addr,
    previous: String,
    targets: Vec<Target>,
}

pub struct Forwarding {
    state: PathBuf,
}

fn ruleset() -> Result<Vec<Value>> {
    let value: Value = serde_json::from_str(&run("nft", &["-j", "-a", "list", "ruleset"], None)?)?;
    Ok(value["nftables"]
        .as_array()
        .context("invalid firewall inventory")?
        .clone())
}

fn apply(script: &str) -> Result<()> {
    if script.is_empty() {
        return Ok(());
    }
    run("nft", &["-c", "-f", "-"], Some(script.as_bytes()))?;
    run("nft", &["-f", "-"], Some(script.as_bytes()))?;
    Ok(())
}

fn wan() -> Result<String> {
    let routes: Value = serde_json::from_str(&run(
        "ip",
        &["-j", "-4", "route", "show", "default", "table", "main"],
        None,
    )?)?;
    let devices: Vec<&str> = routes
        .as_array()
        .context("invalid route inventory")?
        .iter()
        .filter_map(|route| route["dev"].as_str())
        .collect();
    ensure!(
        devices.len() == 1 && rules::interface(devices[0]),
        "relay requires exactly one IPv4 default route interface"
    );
    Ok(devices[0].to_string())
}

fn local_networks(wan: &str) -> Result<Vec<String>> {
    let links: Value =
        serde_json::from_str(&run("ip", &["-j", "-4", "addr", "show", "dev", wan], None)?)?;
    let mut networks = Vec::new();
    for link in links.as_array().context("invalid address inventory")? {
        for address in link["addr_info"].as_array().into_iter().flatten() {
            let (Some(local), Some(prefix)) =
                (address["local"].as_str(), address["prefixlen"].as_u64())
            else {
                continue;
            };
            let ip: Ipv4Addr = local.parse()?;
            let prefix = u32::try_from(prefix.min(32))?;
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            let network = format!("{}/{prefix}", Ipv4Addr::from(u32::from(ip) & mask));
            ensure!(rules::network(&network), "invalid relay address inventory");
            networks.push(network);
        }
    }
    networks.sort();
    networks.dedup();
    Ok(networks)
}

fn active(service: &str) -> Result<bool> {
    let state = run(
        "systemctl",
        &["show", "--property=ActiveState", "--value", service],
        None,
    )?;
    Ok(matches!(
        state.trim(),
        "active" | "activating" | "reloading"
    ))
}

fn ufw_enabled() -> Result<bool> {
    let path = Path::new("/etc/ufw/ufw.conf");
    if !path.exists() {
        return Ok(false);
    }
    let settings = mosaic_core::config::read_bounded(path, 65536, false)?;
    Ok(rules::ufw_enabled(&String::from_utf8_lossy(&settings)))
}

fn managed_firewall() -> Result<()> {
    ensure!(
        !active("firewalld.service")?,
        "firewalld is active; relay forwarding needs a reviewed integration for it"
    );
    ensure!(
        !ufw_enabled()?,
        "ufw is enabled; relay forwarding needs a reviewed integration for it"
    );
    if crate::system::program("iptables-legacy-save").is_ok() {
        let legacy = run("iptables-legacy-save", &[], None)?;
        ensure!(
            rules::legacy_compatible(&legacy),
            "legacy iptables rules need a reviewed forwarding integration"
        );
    }
    Ok(())
}

fn save(path: &Path, state: &State) -> Result<()> {
    use std::io::Write;
    let directory = path.parent().context("invalid state path")?;
    let mut file = tempfile::NamedTempFile::new_in(directory)?;
    file.write_all(&serde_json::to_vec(state)?)?;
    file.as_file().sync_all()?;
    file.persist(path)
        .map_err(|_| anyhow::anyhow!("cannot save forwarding ownership"))?;
    Ok(())
}

fn load(path: &Path) -> Result<Option<State>> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = mosaic_core::config::read_bounded(path, 65536, true)?;
    Ok(Some(serde_json::from_slice(&bytes)?))
}

pub fn private_directory(directory: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !directory.exists() {
        std::fs::create_dir(directory)?;
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
    }
    let metadata = std::fs::symlink_metadata(directory)?;
    ensure!(
        metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o077 == 0,
        "relay state directory must be a root-owned 0700 directory"
    );
    Ok(())
}

fn restore(state: &State) -> Result<()> {
    let items = ruleset()?;
    apply(&rules::removal(&items))?;
    let current = std::fs::read_to_string(FORWARDING)?;
    if current.trim() == "1" && state.previous != "1" {
        let after = ruleset()?;
        let unchanged = rules::targets(&after)
            .map(|now| now.iter().all(|t| state.targets.contains(t)))
            .unwrap_or(false);
        if unchanged {
            std::fs::write(FORWARDING, format!("{}\n", state.previous))?;
        } else {
            eprintln!(
                "relay.forwarding: other forwarding rules appeared while the relay ran; IPv4 forwarding was left enabled"
            );
        }
    }
    Ok(())
}

pub fn recover(directory: &Path) -> Result<()> {
    let path = directory.join(STATE);
    if let Some(state) = load(&path)? {
        restore(&state)?;
        std::fs::remove_file(&path)?;
    }
    Ok(())
}

impl Forwarding {
    pub fn up(directory: &Path, tun: &str, client: Ipv4Addr) -> Result<Self> {
        ensure!(
            rules::interface(tun) && tun.starts_with("mosaic"),
            "invalid relay tunnel name"
        );
        private_directory(directory)?;
        recover(directory)?;
        let state_path = directory.join(STATE);
        managed_firewall()?;
        let items = ruleset()?;
        ensure!(
            rules::removal(&items).is_empty()
                && !items.iter().any(|item| item["chain"]["name"] == EGRESS),
            "Mosaic forwarding rules exist without saved ownership; inspect them before starting"
        );
        let wan = wan()?;
        ensure!(wan != tun, "relay default route uses the tunnel");
        let networks = local_networks(&wan)?;
        let targets = rules::targets(&items)?;
        let previous = std::fs::read_to_string(FORWARDING)?.trim().to_string();
        let script = rules::rules(&Plan {
            tun,
            wan: &wan,
            client,
            local_networks: &networks,
            forwarding_was_enabled: previous == "1",
            targets: &targets,
        });
        run("nft", &["-c", "-f", "-"], Some(script.as_bytes()))
            .context("relay forwarding rules were rejected; nftables 0.9.3 or newer is required")?;
        let state = State {
            tun: tun.into(),
            wan,
            client,
            previous,
            targets,
        };
        save(&state_path, &state)?;
        let installed = run("nft", &["-f", "-"], Some(script.as_bytes()))
            .and_then(|_| std::fs::write(FORWARDING, "1\n").map_err(anyhow::Error::from));
        if let Err(error) = installed {
            let _ = restore(&state);
            let _ = std::fs::remove_file(&state_path);
            return Err(error.context("cannot install relay forwarding"));
        }
        Ok(Self { state: state_path })
    }

    pub fn down(self) -> Result<()> {
        let state = load(&self.state)?.context("forwarding ownership record disappeared")?;
        restore(&state)?;
        std::fs::remove_file(&self.state)?;
        Ok(())
    }
}
