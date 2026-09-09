use crate::{config::Tunnel, linux, pump::PacketIo};
use anyhow::{Context, Result, ensure};
use std::{
    fs::{File, OpenOptions},
    io,
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::Path,
};
use tokio::io::unix::AsyncFd;

pub struct Tun {
    file: AsyncFd<File>,
}

impl Tun {
    pub fn create(c: &Tunnel) -> Result<Self> {
        ensure!(
            !Path::new("/sys/class/net").join(&c.name).exists(),
            "refusing to adopt existing TUN"
        );
        ensure!(
            c.name.starts_with("mosaic")
                && c.name.len() < libc::IFNAMSIZ
                && c.name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "invalid TUN name"
        );
        ensure!(
            c.mtu == 1100 && c.ipv6 == "block",
            "unsupported TUN settings"
        );
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open("/dev/net/tun")
            .context("TUN device unavailable")?;
        let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
        for (to, from) in request.ifr_name.iter_mut().zip(c.name.bytes()) {
            *to = from as libc::c_char;
        }
        request.ifr_ifru.ifru_flags =
            (libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_TUN_EXCL) as libc::c_short;
        linux::check(unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF as _, &request) })
            .context("cannot create exclusive TUN")?;
        std::fs::write(
            format!("/proc/sys/net/ipv6/conf/{}/disable_ipv6", c.name),
            "1",
        )
        .context("cannot disable IPv6 on the new TUN")?;
        linux::command(
            "ip",
            &[
                "link",
                "set",
                "dev",
                &c.name,
                "mtu",
                "1100",
                "txqueuelen",
                "256",
            ],
        )?;
        linux::command("ip", &["addr", "add", &c.address, "dev", &c.name])?;
        linux::command("ip", &["link", "set", "dev", &c.name, "up"])?;
        Ok(Self {
            file: AsyncFd::new(file)?,
        })
    }
}

impl PacketIo for Tun {
    async fn receive(&self, bytes: &mut [u8]) -> Result<usize> {
        loop {
            let mut ready = self.file.readable().await?;
            match ready.try_io(|fd| {
                let result = unsafe {
                    libc::read(
                        fd.get_ref().as_raw_fd(),
                        bytes.as_mut_ptr().cast(),
                        bytes.len(),
                    )
                };
                if result < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(result as usize)
                }
            }) {
                Ok(result) => return Ok(result?),
                Err(_) => continue,
            }
        }
    }

    async fn send(&self, bytes: &[u8]) -> Result<()> {
        loop {
            let mut ready = self.file.writable().await?;
            match ready.try_io(|fd| {
                let result = unsafe {
                    libc::write(fd.get_ref().as_raw_fd(), bytes.as_ptr().cast(), bytes.len())
                };
                if result < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(result as usize)
                }
            }) {
                Ok(result) => {
                    ensure!(result? == bytes.len(), "partial TUN packet write");
                    return Ok(());
                }
                Err(_) => continue,
            }
        }
    }
}
