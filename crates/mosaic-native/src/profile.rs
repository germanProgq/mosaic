use anyhow::{Result, ensure};
use mosaic_core::config::{ClientConfig, certificates, decode_token, read_bounded, read_token};
use serde::{Deserialize, Serialize};
#[cfg(not(target_os = "windows"))]
use std::fs::OpenOptions;
use std::{io::Write, path::Path};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub config: ClientConfig,
    pub certificate: String,
    pub token: String,
}

impl Profile {
    pub fn read(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= 98304,
            "private configuration exceeds size limit"
        );
        let profile: Self = serde_json::from_slice(bytes)
            .map_err(|_| anyhow::anyhow!("invalid private configuration"))?;
        profile.config.validate()?;
        ensure!(
            profile.config.mode == "native_tun",
            "native TUN configuration required"
        );
        ensure!(
            profile.certificate.len() <= 32768,
            "trust certificate exceeds size limit"
        );
        decode_token(profile.token.as_bytes())?;
        let mut roots = rustls::RootCertStore::empty();
        for cert in
            rustls_pemfile::certs(&mut std::io::BufReader::new(profile.certificate.as_bytes()))
        {
            roots
                .add(cert.map_err(|_| anyhow::anyhow!("invalid trust certificate"))?)
                .map_err(|_| anyhow::anyhow!("invalid trust certificate"))?;
        }
        ensure!(!roots.is_empty(), "missing trust certificate");
        Ok(profile)
    }

    pub fn load(path: &Path) -> Result<Self> {
        Self::read(&read_bounded(path, 98304, true)?)
    }

    pub fn export(config: &Path, output: &Path) -> Result<()> {
        let mut config = ClientConfig::load(config)?;
        ensure!(
            config.mode != "isolated_tun",
            "do not export a shared-node configuration for host networking"
        );
        config.check_credentials()?;
        if config.mode == "diagnostic" {
            config.mode = "native_tun".into();
            config.network.change_host_network = true;
            config.tunnel = Some(mosaic_core::config::Tunnel {
                name: "mosaic0".into(),
                address: "10.77.0.2/30".into(),
                peer: "10.77.0.1".parse()?,
                mtu: 1100,
                ipv6: "block".into(),
            });
            config.dns = Some(mosaic_core::config::Dns {
                servers: vec!["1.1.1.1".parse()?],
            });
        }
        config.validate()?;
        certificates(&config.tls.trust_cert)?;
        let token = mosaic_core::session::hex(&read_token(&config.auth.token_file)?);
        let certificate = String::from_utf8(read_bounded(&config.tls.trust_cert, 32768, false)?)?;
        let mut profile = Self {
            config,
            certificate,
            token,
        };
        profile.config.tls.trust_cert = "relay.crt".into();
        profile.config.auth.token_file = "client.token".into();
        private_file(output, &serde_json::to_vec(&profile)?)
    }

    pub fn install(&self, directory: &Path) -> Result<ClientConfig> {
        let mut config = self.config.clone();
        config.tls.trust_cert = directory.join("relay.crt");
        config.auth.token_file = directory.join("client.token");
        private_file(&config.tls.trust_cert, self.certificate.as_bytes())?;
        private_file(&config.auth.token_file, self.token.as_bytes())?;
        config.check_credentials()?;
        Ok(config)
    }
}

pub fn private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    #[cfg(target_os = "windows")]
    let mut file = crate::windows::private_file(path)?;
    #[cfg(not(target_os = "windows"))]
    let mut file = {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        options
            .open(path)
            .map_err(|_| anyhow::anyhow!("cannot create new private file"))?
    };
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
