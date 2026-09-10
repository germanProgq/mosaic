//! Strict, bounded configuration parsing. Errors never include configuration values.
use anyhow::{Result, bail, ensure};
use rustls::pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use std::{
    io::{BufReader, Read},
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
};

const CONFIG_BYTES: u64 = 64 * 1024;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub version: u8,
    #[serde(rename = "type")]
    pub kind: String,
    pub mode: String,
    pub server: Server,
    pub transport: Transport,
    pub tls: ClientTls,
    pub auth: Auth,
    pub network: Network,
    pub limits: Limits,
    pub isolation: Option<Isolation>,
    pub tunnel: Option<Tunnel>,
    pub dns: Option<Dns>,
    pub test_limits: Option<TestLimits>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Server {
    pub address: SocketAddr,
    pub name: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Transport {
    #[serde(rename = "type")]
    pub kind: String,
    pub alpn: String,
    pub idle_timeout_s: u64,
    pub keepalive_s: u64,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientTls {
    pub trust_cert: PathBuf,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Auth {
    pub token_file: PathBuf,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    pub outbound_only: bool,
    pub change_host_network: bool,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub max_control_bytes: usize,
    pub queue_packets: usize,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Isolation {
    pub namespace: String,
    pub transport_socket: String,
    pub host_network_changes: String,
    pub preserve_existing_vpn: bool,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Tunnel {
    pub name: String,
    pub address: String,
    pub peer: Ipv4Addr,
    pub mtu: u16,
    pub ipv6: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Dns {
    pub servers: Vec<Ipv4Addr>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TestLimits {
    pub max_mbps: f64,
    pub parallel_flows: u8,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfig {
    pub version: u8,
    #[serde(rename = "type")]
    pub kind: String,
    pub listen: SocketAddr,
    pub transport: Transport,
    pub tls: RelayTls,
    pub auth: Auth,
    pub limits: Limits,
    pub tunnel: Tunnel,
    pub allowed_client: Ipv4Addr,
    pub tunnel_owners: u8,
    pub fetch: Fetch,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelayTls {
    pub cert: PathBuf,
    pub key: PathBuf,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Fetch {
    pub allow: Vec<Destination>,
    pub max_requests: u16,
    pub max_bytes: u64,
    pub timeout_s: u64,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Destination {
    pub host: String,
    pub port: u16,
}

pub fn read_bounded(path: &Path, limit: u64, private: bool) -> Result<Vec<u8>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | if private { libc::O_NOFOLLOW } else { 0 });
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let f = options
        .open(path)
        .map_err(|_| anyhow::anyhow!("required file cannot be opened"))?;
    let meta = f
        .metadata()
        .map_err(|_| anyhow::anyhow!("cannot inspect required file"))?;
    ensure!(
        meta.is_file() && meta.len() <= limit,
        "required file must be regular and within its size limit"
    );
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            meta.permissions().mode() & 0o077 == 0,
            "secret file must have owner-only permissions (0600)"
        );
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        ensure!(
            meta.file_attributes()
                & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
                == 0,
            "required file must not be a reparse point"
        );
        if private {
            crate::private_file::check(&f)?;
        }
    }
    let mut data = Vec::new();
    f.take(limit + 1)
        .read_to_end(&mut data)
        .map_err(|_| anyhow::anyhow!("cannot read required file"))?;
    ensure!(
        data.len() as u64 <= limit,
        "required file exceeds size limit"
    );
    Ok(data)
}

fn parse<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = read_bounded(path, CONFIG_BYTES, false)?;
    serde_json::from_slice(&bytes).map_err(|e| {
        anyhow::anyhow!(
            "invalid configuration schema at line {}, column {}",
            e.line(),
            e.column()
        )
    })
}
fn resolve(base: &Path, path: &mut PathBuf) {
    if path.is_relative() {
        *path = base.join(&*path);
    }
}
fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 15
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn dns_name(s: &str) -> bool {
    s.len() <= 253
        && s.contains('.')
        && s.parse::<std::net::IpAddr>().is_err()
        && s.split('.').all(|p| {
            !p.is_empty()
                && p.len() <= 63
                && !p.starts_with('-')
                && !p.ends_with('-')
                && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
fn common(version: u8, kind: &str, t: &Transport, l: &Limits) -> Result<()> {
    ensure!(
        version == 2 && kind == "mosaic",
        "expected Mosaic configuration version 2"
    );
    ensure!(
        t.kind == "quic" && t.alpn == "mosaic-poc/2",
        "expected QUIC with prototype ALPN mosaic-poc/2"
    );
    ensure!(
        t.idle_timeout_s == 15 && t.keepalive_s > 0 && t.keepalive_s <= 5,
        "idle timeout must be 15 seconds and keepalive 1..5 seconds"
    );
    ensure!(
        (1..=4096).contains(&l.max_control_bytes) && (1..=256).contains(&l.queue_packets),
        "control/queue limits exceed prototype bounds"
    );
    Ok(())
}
pub fn tunnel(t: &Tunnel) -> Result<Ipv4Addr> {
    ensure!(
        identifier(&t.name) && t.name.starts_with("mosaic"),
        "TUN name must be a Mosaic-owned interface name"
    );
    ensure!(
        t.mtu == 1100 && t.ipv6 == "block",
        "prototype requires MTU 1100 and IPv6 block"
    );
    let (ip, prefix) = t
        .address
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("invalid tunnel CIDR"))?;
    let ip: Ipv4Addr = ip
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid tunnel IPv4 address"))?;
    ensure!(
        prefix == "30" && ip.is_private() && t.peer.is_private(),
        "tunnel must use a private IPv4 /30"
    );
    let a = u32::from(ip);
    let b = u32::from(t.peer);
    ensure!(
        a & !3 == b & !3 && a != b && (a & 3 == 1 || a & 3 == 2) && (b & 3 == 1 || b & 3 == 2),
        "tunnel endpoints must be distinct usable addresses in the same /30"
    );
    Ok(ip)
}

impl ClientConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let mut c: Self = parse(path)?;
        c.validate()?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        resolve(base, &mut c.tls.trust_cert);
        resolve(base, &mut c.auth.token_file);
        Ok(c)
    }
    pub fn validate(&self) -> Result<()> {
        common(self.version, &self.kind, &self.transport, &self.limits)?;
        ensure!(
            self.network.outbound_only
                && (self.network.change_host_network == (self.mode == "native_tun")),
            "only native TUN mode may request host network changes"
        );
        ensure!(
            self.server.address.port() != 0
                && !self.server.address.ip().is_unspecified()
                && !self.server.address.ip().is_multicast(),
            "invalid relay socket address"
        );
        ensure!(
            dns_name(&self.server.name),
            "server name must be a DNS certificate name"
        );
        match self.mode.as_str() {
            "native_tun" => {
                ensure!(
                    self.isolation.is_none() && self.test_limits.is_none(),
                    "native mode must not contain shared-node isolation settings"
                );
                ensure!(
                    self.server.address.is_ipv4(),
                    "native mode currently requires an IPv4 relay"
                );
                tunnel(
                    self.tunnel
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("missing native tunnel settings"))?,
                )?;
                ensure!(
                    self.dns
                        .as_ref()
                        .is_some_and(|dns| dns.servers == [Ipv4Addr::new(1, 1, 1, 1)]),
                    "native DNS must use only 1.1.1.1 through the tunnel"
                );
            }
            "diagnostic" => ensure!(
                self.isolation.is_none()
                    && self.tunnel.is_none()
                    && self.dns.is_none()
                    && self.test_limits.is_none(),
                "diagnostic mode must not contain TUN settings"
            ),
            "isolated_tun" => {
                let i = self
                    .isolation
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("missing isolation settings"))?;
                ensure!(
                    identifier(&i.namespace)
                        && i.namespace.starts_with("mosaic-")
                        && i.transport_socket == "created_in_host_namespace"
                        && i.host_network_changes == "forbidden"
                        && i.preserve_existing_vpn,
                    "unsafe isolation settings"
                );
                tunnel(
                    self.tunnel
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("missing tunnel settings"))?,
                )?;
                let d = self
                    .dns
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("missing namespace DNS"))?;
                ensure!(
                    d.servers == [Ipv4Addr::new(1, 1, 1, 1)],
                    "namespace DNS must use only 1.1.1.1"
                );
                let l = self
                    .test_limits
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("missing test limits"))?;
                ensure!(
                    l.max_mbps > 0.0 && l.max_mbps <= 1.0 && l.parallel_flows == 1,
                    "shared-node tests require at most 1 Mbit/s and one flow"
                );
            }
            _ => bail!("unsupported client mode"),
        }
        Ok(())
    }
    pub fn check_credentials(&self) -> Result<()> {
        read_token(&self.auth.token_file)?;
        let certs = certificates(&self.tls.trust_cert)?;
        let mut roots = rustls::RootCertStore::empty();
        for cert in certs {
            roots
                .add(cert)
                .map_err(|_| anyhow::anyhow!("invalid trust certificate"))?;
        }
        Ok(())
    }
}
impl RelayConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let mut c: Self = parse(path)?;
        common(c.version, &c.kind, &c.transport, &c.limits)?;
        ensure!(
            c.listen.is_ipv4() && c.listen.port() != 0 && !c.listen.ip().is_multicast(),
            "relay requires an IPv4 listen address and nonzero port"
        );
        tunnel(&c.tunnel)?;
        ensure!(
            c.allowed_client == c.tunnel.peer && c.tunnel_owners == 1,
            "relay requires one tunnel owner matching its peer"
        );
        ensure!(
            c.fetch.allow.len() <= 16
                && (1..=10).contains(&c.fetch.max_requests)
                && (1..=33554432).contains(&c.fetch.max_bytes)
                && (1..=300).contains(&c.fetch.timeout_s),
            "invalid fetch limits"
        );
        ensure!(
            c.fetch
                .allow
                .iter()
                .all(|d| dns_name(&d.host) && d.port == 443),
            "fetch allowlist requires explicit DNS names and HTTPS port 443"
        );
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        resolve(base, &mut c.tls.cert);
        resolve(base, &mut c.tls.key);
        resolve(base, &mut c.auth.token_file);
        Ok(c)
    }
    pub fn check_credentials(&self) -> Result<()> {
        read_token(&self.auth.token_file)?;
        let certs = certificates(&self.tls.cert)?;
        let key = read_bounded(&self.tls.key, 16384, true)?;
        let key = rustls_pemfile::private_key(&mut BufReader::new(key.as_slice()))
            .map_err(|_| anyhow::anyhow!("invalid relay private key"))?
            .ok_or_else(|| anyhow::anyhow!("missing relay private key"))?;
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|_| {
                anyhow::anyhow!("relay certificate and key are invalid or do not match")
            })?;
        Ok(())
    }
}
pub fn certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let bytes = read_bounded(path, 32768, false)?;
    let certs: Vec<_> = rustls_pemfile::certs(&mut BufReader::new(bytes.as_slice()))
        .collect::<std::result::Result<_, _>>()
        .map_err(|_| anyhow::anyhow!("invalid certificate PEM"))?;
    ensure!(
        !certs.is_empty(),
        "certificate file contains no certificates"
    );
    Ok(certs)
}
pub fn read_token(path: &Path) -> Result<[u8; 32]> {
    let raw = read_bounded(path, 66, true)?;
    let raw = raw.strip_suffix(b"\n").unwrap_or(&raw);
    let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
    decode_token(raw)
}
pub fn decode_token(raw: &[u8]) -> Result<[u8; 32]> {
    ensure!(
        raw.len() == 64 && raw.iter().all(u8::is_ascii_hexdigit),
        "token must encode exactly 32 bytes as 64 hex digits"
    );
    let mut token = [0u8; 32];
    for (i, pair) in raw.chunks_exact(2).enumerate() {
        fn hex(x: u8) -> u8 {
            if x.is_ascii_digit() {
                x - b'0'
            } else {
                x.to_ascii_lowercase() - b'a' + 10
            }
        }
        token[i] = hex(pair[0]) * 16 + hex(pair[1]);
    }
    Ok(token)
}
