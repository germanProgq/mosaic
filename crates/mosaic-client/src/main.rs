mod diagnostic;
mod preflight;
use clap::{Parser, Subcommand};
use mosaic_core::{
    config::ClientConfig,
    report::{Report, Status},
};
use std::{path::PathBuf, process::ExitCode};

#[derive(Parser)]
#[command(version, about = "Mosaic native client — native diagnostics")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
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
    #[command(about = "Run authenticated session, stream and datagram diagnostics.")]
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
#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let (config, schema_only, output, preflight, diagnostic) = match cli.command {
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
