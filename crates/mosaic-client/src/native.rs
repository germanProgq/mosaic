use crate::Command;
use anyhow::Result;
use std::process::ExitCode;

pub fn handles(command: &Command) -> bool {
    matches!(
        command,
        Command::Setup { .. }
            | Command::ExportConfig { .. }
            | Command::Import { .. }
            | Command::Connect
            | Command::Disconnect
            | Command::Status
            | Command::Uninstall
    )
}

pub fn run(command: Command) -> ExitCode {
    match execute(command) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("FAIL native: {error}");
            ExitCode::from(1)
        }
    }
}

fn execute(command: Command) -> Result<u8> {
    if let Command::ExportConfig { config, output } = command {
        mosaic_native::profile::Profile::export(&config, &output).map_err(|_| {
            anyhow::anyhow!(
                "cannot export private configuration; validate input and use a new output path"
            )
        })?;
        println!(
            "PASS: private native configuration exported; keep it out of logs and source control"
        );
        return Ok(0);
    }
    #[cfg(target_os = "macos")]
    {
        let local = std::env::current_exe()?
            .parent()
            .unwrap()
            .join("mosaic-control");
        let installed =
            std::path::Path::new("/Applications/Mosaic.app/Contents/MacOS/mosaic-control");
        let helper = if local.is_file() {
            local.as_path()
        } else {
            installed
        };
        anyhow::ensure!(
            helper.is_file(),
            "install the signed Mosaic.app native package in Applications first"
        );
        let mut process = std::process::Command::new(helper);
        match command {
            Command::Setup {
                user: None,
                owner_sid: None,
            } => {
                process.arg("setup");
            }
            Command::Import { config } => {
                process.arg("import").arg(config.canonicalize()?);
            }
            Command::Connect => {
                process.arg("connect");
            }
            Command::Disconnect => {
                process.arg("disconnect");
            }
            Command::Status => {
                process.arg("status");
            }
            Command::Uninstall => {
                process.arg("uninstall");
            }
            _ => anyhow::bail!("unsupported native command options on macOS"),
        }
        Ok(if process.status()?.success() { 0 } else { 1 })
    }
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        if let Command::Setup { user, owner_sid } = command {
            #[cfg(target_os = "linux")]
            {
                anyhow::ensure!(
                    owner_sid.is_none(),
                    "owner-sid is only available on Windows"
                );
                mosaic_native::linux::setup(user)?;
            }
            #[cfg(target_os = "windows")]
            {
                anyhow::ensure!(
                    user.is_none(),
                    "Windows setup uses the installing user's identity"
                );
                mosaic_native::windows::setup(owner_sid.as_deref())?;
            }
            println!("PASS: native service installed");
            return Ok(0);
        }
        if matches!(command, Command::Uninstall) {
            #[cfg(target_os = "linux")]
            mosaic_native::linux::uninstall()?;
            #[cfg(target_os = "windows")]
            mosaic_native::windows::uninstall()?;
            println!("PASS: native service removed");
            return Ok(0);
        }
        use mosaic_native::service::Request;
        let request = match command {
            Command::Import { config } => {
                let bytes = mosaic_core::config::read_bounded(&config, 98304, true)?;
                mosaic_native::profile::Profile::read(&bytes)?;
                Request::Import {
                    profile: String::from_utf8(bytes)?,
                }
            }
            Command::Connect => Request::Connect,
            Command::Disconnect => Request::Disconnect,
            Command::Status => Request::Status,
            _ => anyhow::bail!("unsupported native command"),
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        #[cfg(target_os = "linux")]
        let status = runtime.block_on(mosaic_native::service::request(request))?;
        #[cfg(target_os = "windows")]
        let status = runtime.block_on(mosaic_native::windows::request(request))?;
        println!(
            "{}: {} (IPv6 {})",
            match status.state {
                mosaic_core::native::State::Disconnected => "disconnected",
                mosaic_core::native::State::Connecting => "connecting",
                mosaic_core::native::State::Connected => "connected",
                mosaic_core::native::State::Reconnecting => "reconnecting",
                mosaic_core::native::State::Failed => "failed",
            },
            status.detail,
            status.ipv6
        );
        Ok(if status.state == mosaic_core::native::State::Failed {
            1
        } else {
            0
        })
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    anyhow::bail!("use the installed native mobile application on this operating system")
}
