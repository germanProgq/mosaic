use anyhow::{Context, Result, ensure};
use std::{
    io,
    net::UdpSocket,
    os::fd::AsRawFd,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub fn command(program: &str, args: &[&str]) -> Result<()> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("required Linux command unavailable")?;
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            ensure!(status.success(), "Linux setup command failed");
            return Ok(());
        }
        if start.elapsed() >= Duration::from_secs(5) {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("Linux setup command exceeded five seconds");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

pub fn cookie(socket: &UdpSocket) -> Result<u64> {
    let mut cookie = 0u64;
    let mut length = std::mem::size_of::<u64>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_NETNS_COOKIE,
            (&mut cookie as *mut u64).cast(),
            &mut length,
        )
    };
    ensure!(
        result == 0 && length as usize == std::mem::size_of::<u64>(),
        "socket namespace cookie unavailable"
    );
    Ok(cookie)
}

pub fn check(result: libc::c_int) -> io::Result<()> {
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
