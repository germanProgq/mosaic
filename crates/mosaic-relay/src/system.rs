use anyhow::{Context, Result, bail, ensure};
use std::{
    io::{Read, Write},
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub fn program(name: &str) -> Result<&'static str> {
    let candidates: &[&'static str] = match name {
        "ip" => &["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"],
        "nft" => &["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"],
        "systemctl" => &["/usr/bin/systemctl", "/bin/systemctl"],
        "iptables-legacy-save" => &[
            "/usr/sbin/iptables-legacy-save",
            "/sbin/iptables-legacy-save",
        ],
        _ => bail!("unsupported system command"),
    };
    candidates
        .iter()
        .copied()
        .find(|path| Path::new(path).is_file())
        .with_context(|| format!("required command {name} is not installed"))
}

pub fn run(name: &str, arguments: &[&str], input: Option<&[u8]>) -> Result<String> {
    let mut child = Command::new(program(name)?)
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("cannot start {name}"))?;
    if let Some(input) = input {
        child
            .stdin
            .take()
            .context("command input unavailable")?
            .write_all(input)?;
    }
    let mut stdout = child.stdout.take().context("command output unavailable")?;
    let mut stderr = child.stderr.take().context("command errors unavailable")?;
    let reader = std::thread::spawn(move || {
        let mut output = String::new();
        stdout.read_to_string(&mut output).map(|_| output)
    });
    let errors = std::thread::spawn(move || {
        let mut output = String::new();
        stderr.read_to_string(&mut output).map(|_| output)
    });
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if start.elapsed() >= Duration::from_secs(15) {
            let _ = child.kill();
            let _ = child.wait();
            bail!("{name} exceeded fifteen seconds");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let output = reader
        .join()
        .map_err(|_| anyhow::anyhow!("command output reader failed"))??;
    let errors = errors
        .join()
        .map_err(|_| anyhow::anyhow!("command error reader failed"))??;
    let detail: String = errors.trim().chars().take(400).collect();
    ensure!(status.success(), "{name} command failed: {detail}");
    Ok(output)
}

pub fn root() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "relay setup requires root privileges"
    );
    Ok(())
}
