pub const RESOLVER: &str = "nameserver 1.1.1.1\noptions timeout:2 attempts:1 ndots:1\n";

pub fn name_services(original: &str) -> String {
    let mut result = String::new();
    for line in original.lines() {
        let line = line.split('#').next().unwrap_or_default().trim_end();
        if line.is_empty()
            || line
                .split_once(':')
                .is_some_and(|(key, _)| key.trim() == "hosts")
        {
            continue;
        }
        result.push_str(line);
        result.push('\n');
    }
    result.push_str("hosts: dns\n");
    result
}

#[cfg(target_os = "linux")]
mod system {
    use super::*;
    use crate::linux::{self, check};
    use anyhow::{Context, Result, ensure};
    use std::{
        ffi::CString,
        fs::{self, File},
        io::Write,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::fs::MetadataExt,
        },
        path::Path,
    };

    fn mount(source: Option<&str>, target: &str, flags: libc::c_ulong) -> Result<()> {
        let source = source.map(CString::new).transpose()?;
        let target = CString::new(target)?;
        check(unsafe {
            libc::mount(
                source.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
                target.as_ptr(),
                std::ptr::null(),
                flags,
                std::ptr::null(),
            )
        })
        .context("private resolver mount failed")?;
        Ok(())
    }

    fn file(target: &str, contents: &str) -> Result<()> {
        let name = CString::new("mosaic-resolver")?;
        let fd = unsafe {
            libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING)
        };
        check(fd)?;
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(contents.as_bytes())?;
        check(unsafe { libc::fchmod(fd, 0o444) })?;
        check(unsafe {
            libc::fcntl(
                fd,
                libc::F_ADD_SEALS,
                libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL,
            )
        })?;
        mount(
            Some(&format!("/proc/self/fd/{}", file.as_raw_fd())),
            target,
            libc::MS_BIND,
        )?;
        mount(
            None,
            target,
            libc::MS_BIND
                | libc::MS_REMOUNT
                | libc::MS_RDONLY
                | libc::MS_NOSUID
                | libc::MS_NODEV
                | libc::MS_NOEXEC,
        )?;
        Ok(())
    }

    pub fn private_dns() -> Result<()> {
        let parent = unsafe { libc::getppid() };
        ensure!(
            fs::metadata("/proc/self/ns/mnt")?.ino()
                != fs::metadata(format!("/proc/{parent}/ns/mnt"))?.ino(),
            "private mount namespace required before DNS setup"
        );
        mount(None, "/", libc::MS_REC | libc::MS_PRIVATE)?;
        let original = crate::config::read_bounded(Path::new("/etc/nsswitch.conf"), 65536, false)?;
        let names = name_services(std::str::from_utf8(&original)?);
        file("/etc/resolv.conf", RESOLVER)?;
        file("/etc/nsswitch.conf", &names)?;
        for target in [
            "/run/nscd/socket",
            "/var/run/nscd/socket",
            "/var/cache/nscd/hosts",
            "/run/nscd/hosts",
            "/var/run/nscd/hosts",
        ] {
            if Path::new(target).try_exists()? {
                file(target, "")?;
            }
        }
        Ok(())
    }

    pub fn default_route(tun: &str) -> Result<()> {
        let parent = unsafe { libc::getppid() };
        ensure!(
            fs::metadata("/proc/self/ns/net")?.ino()
                != fs::metadata(format!("/proc/{parent}/ns/net"))?.ino(),
            "private network namespace required before routing setup"
        );
        linux::command(
            "ip",
            &[
                "-4", "route", "add", "default", "dev", tun, "proto", "static",
            ],
        )
    }
}

#[cfg(target_os = "linux")]
pub use system::{default_route, private_dns};
