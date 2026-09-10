mod diagnostic;
mod fetch;
mod native;
mod netns_launcher;
mod preflight;
use clap::{Parser, Subcommand};
use mosaic_core::{
    config::ClientConfig,
    report::{Report, Status},
};
use std::{path::PathBuf, process::ExitCode};

#[derive(Parser)]
#[command(
    version,
    about = "Mosaic native VPN, authenticated diagnostics and isolated Linux testing"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    #[command(about = "Install or activate Mosaic's native networking component.")]
    Setup {
        #[arg(long)]
        user: Option<u32>,
        #[arg(long)]
        owner_sid: Option<String>,
    },
    #[command(
        about = "Export a private native VPN configuration with embedded client credentials."
    )]
    ExportConfig {
        #[arg(short, long)]
        config: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    #[command(
        about = "Import a private .mosaic configuration into the installed native component."
    )]
    Import {
        #[arg(short, long)]
        config: PathBuf,
    },
    #[command(about = "Connect ordinary application traffic through the installed native VPN.")]
    Connect,
    #[command(about = "Disconnect and remove Mosaic-owned networking state.")]
    Disconnect,
    #[command(about = "Read the installed native VPN connection status.")]
    Status,
    #[command(about = "Remove the disconnected native component and its private configuration.")]
    Uninstall,
    #[command(
        about = "Fetch verified HTTPS from this process through the relay; other application traffic is unchanged."
    )]
    Fetch {
        #[arg(short, long)]
        config: PathBuf,
        url: String,
        #[arg(long)]
        upload: Option<PathBuf>,
        #[arg(long)]
        expect_sha256: Option<String>,
        #[arg(long)]
        report: Option<PathBuf>,
    },
    #[command(about = "Run an isolated Linux TUN with an inherited host UDP socket and VPN guard.")]
    IsolatedUp {
        #[arg(short, long)]
        config: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        baseline: PathBuf,
        #[arg(long, default_value = "tools/network/isolation.py")]
        guard: PathBuf,
        #[arg(long)]
        report: Option<PathBuf>,
    },
    #[command(about = "Remove an inactive launcher's recorded namespace and worker.")]
    IsolatedDown {
        #[arg(long)]
        namespace: String,
        #[arg(long)]
        report: Option<PathBuf>,
    },
    #[command(
        about = "Run an application with namespace routing and private DNS as the test user."
    )]
    IsolatedExec {
        #[arg(long)]
        namespace: String,
        #[arg(required = true, last = true)]
        args: Vec<std::ffi::OsString>,
    },
    #[command(hide = true)]
    IsolatedWorker {
        #[arg(short, long)]
        config: PathBuf,
        #[arg(long)]
        fd: i32,
        #[arg(long)]
        cookie: u64,
        #[arg(long)]
        uid: u32,
    },
    /// Validate the strict config schema and local credential files without network activity.
    CheckConfig {
        #[arg(short, long)]
        config: PathBuf,
        /// Validate examples without requiring provisioned credentials.
        #[arg(long)]
        schema_only: bool,
        #[arg(long)]
        report: Option<PathBuf>,
    },
    #[command(
        about = "Test authenticated sessions, streams and datagrams; does not connect a desktop VPN."
    )]
    Test {
        #[arg(short, long)]
        config: PathBuf,
        #[arg(long, default_value = "stream-echo", value_parser = ["stream-echo", "session", "datagram-echo"])]
        case: String,
        #[arg(long, default_value_t = 1000)]
        count: usize,
        #[arg(long, default_value_t = 1100)]
        size: usize,
        #[arg(long, default_value_t = 50)]
        rate: u32,
        #[arg(long)]
        report: Option<PathBuf>,
    },
    /// Run bounded outbound DNS/HTTPS checks; deployment gates remain separate.
    Preflight {
        #[arg(short, long)]
        config: PathBuf,
        #[arg(long)]
        report: Option<PathBuf>,
    },
}
fn main() -> ExitCode {
    let cli = Cli::parse();
    if native::handles(&cli.command) {
        return native::run(cli.command);
    }
    match cli.command {
        Command::IsolatedUp {
            config,
            policy,
            baseline,
            guard,
            report,
        } => netns_launcher::launch(netns_launcher::Options {
            config: &config,
            policy: &policy,
            baseline: &baseline,
            guard: &guard,
            output: report.as_deref(),
        }),
        Command::IsolatedDown { namespace, report } => {
            netns_launcher::cleanup(&namespace, report.as_deref())
        }
        Command::IsolatedExec { namespace, args } => netns_launcher::execute(&namespace, &args),
        Command::IsolatedWorker {
            config,
            fd,
            cookie,
            uid,
        } => match netns_launcher::worker(&config, fd, cookie, uid) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => {
                eprintln!(
                    "FAIL isolation.worker: namespace, inherited socket, authentication or packet pump failed"
                );
                ExitCode::from(1)
            }
        },
        command => match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime.block_on(run(command)),
            Err(_) => ExitCode::from(1),
        },
    }
}

async fn run(command: Command) -> ExitCode {
    if let Command::Fetch {
        config,
        url,
        upload,
        expect_sha256,
        report,
    } = command
    {
        return fetch::run(
            &config,
            &url,
            upload.as_deref(),
            expect_sha256.as_deref(),
            report.as_deref(),
        )
        .await;
    }
    let (config, schema_only, output, preflight, diagnostic) = match command {
        Command::CheckConfig {
            config,
            schema_only,
            report,
        } => (config, schema_only, report, false, None),
        Command::Preflight { config, report } => (config, false, report, true, None),
        Command::Test {
            config,
            report,
            case,
            count,
            size,
            rate,
        } => (
            config,
            false,
            report,
            false,
            Some((
                case,
                mosaic_core::quic::DatagramOptions { count, size, rate },
            )),
        ),
        Command::IsolatedUp { .. }
        | Command::IsolatedDown { .. }
        | Command::IsolatedExec { .. }
        | Command::IsolatedWorker { .. } => return ExitCode::from(2),
        _ => return ExitCode::from(2),
    };
    let mut report = Report::new(if schema_only {
        "schema-only"
    } else {
        "local-only"
    });
    if diagnostic.is_some() {
        report.check_level = 2;
        report.scope = "authenticated-diagnostics".into();
    }
    match ClientConfig::load(&config) {
        Err(e) => report.add("config.schema", Status::Fail, &e.to_string()),
        Ok(c) => {
            report.add(
                "config.schema",
                Status::Pass,
                "strict version-2 schema and safety constraints validated",
            );
            if !schema_only {
                match c.check_credentials() {
                    Err(e) => report.add("config.credentials", Status::Fail, &e.to_string()),
                    Ok(()) => {
                        report.add("config.credentials", Status::Pass, "trust material and owner-only 32-byte token validated; server SAN is checked during TLS");
                        if let Some((case, options)) = &diagnostic {
                            diagnostic::run(&c, case, options, &mut report).await;
                        }
                        if preflight {
                            preflight::run(&c, &mut report).await;
                        }
                    }
                }
            }
        }
    }
    if report.emit(output.as_deref()).is_err() {
        eprintln!("FAIL report.write: cannot write new report file");
        return ExitCode::from(1);
    }
    ExitCode::from(report.exit_code())
}
