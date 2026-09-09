use clap::Parser;
use mosaic_core::{
    config::RelayConfig,
    quic,
    report::{Report, Status},
    session,
};
use std::{path::PathBuf, process::ExitCode};
#[derive(Parser)]
#[command(
    version,
    about = "Mosaic relay — configuration validation and authenticated diagnostics"
)]
struct Cli {
    #[arg(short, long)]
    config: PathBuf,
    #[arg(long, conflicts_with = "diagnostic_only")]
    check_config: bool,
    #[arg(long, requires = "check_config")]
    schema_only: bool,
    #[arg(long)]
    diagnostic_only: bool,
    #[arg(long, conflicts_with_all = ["diagnostic_only", "check_config"])]
    tunnel: bool,
    #[arg(long, conflicts_with_all = ["diagnostic_only", "check_config"])]
    fetch: bool,
    #[arg(long)]
    report: Option<PathBuf>,
}

async fn shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let Ok(mut term) = signal(SignalKind::terminate()) else {
            return;
        };
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Cli::parse();
    let mut report = Report::new(if args.schema_only {
        "schema-only"
    } else if args.diagnostic_only {
        "diagnostic-only"
    } else {
        "relay-config-only"
    });
    if args.diagnostic_only {
        report.check_level = 2;
    }
    let mut tunnel = None;
    let mut endpoint = None;
    let mut settings = None;
    match RelayConfig::load(&args.config) {
        Err(e) => report.add("config.schema", Status::Fail, &e.to_string()),
        Ok(c) => {
            report.add(
                "config.schema",
                Status::Pass,
                "relay schema, tunnel ownership and resource bounds validated",
            );
            if !args.schema_only {
                match c.check_credentials() {
                    Err(e) => report.add("config.credentials", Status::Fail, &e.to_string()),
                    Ok(()) => {
                        report.add(
                            "config.credentials",
                            Status::Pass,
                            "certificate/key pairing and owner-only token validated",
                        );
                        if (args.diagnostic_only || args.fetch || args.tunnel)
                            && (!args.tunnel || cfg!(target_os = "linux"))
                        {
                            match session::Settings::load(&c).and_then(|s| quic::relay_endpoint(&c).map(|e| (e, s))) {
                                Ok((e, mut s)) => {
                                    if args.fetch {
                                        s.enable_fetch(c.fetch);
                                        report.check_level = 4;
                                        report.scope = "fetch-service".into();
                                        report.add("relay.fetch_listen", Status::Pass, "Authenticated allowlisted TCP service ready; bounded IPv4 HTTPS forwarding; no TUN egress assertion");
                                    }
                                    if args.tunnel {
                                        tunnel = Some(c.tunnel);
                                        report.check_level = if args.fetch { 4 } else { 3 };
                                        report.scope = if args.fetch { "tunnel-and-fetch-service" } else { "tunnel-service" }.into();
                                        report.add("relay.tunnel_listen", Status::Pass, "Authenticated tunnel service ready; one owner; TUN opens only after Ready; forwarding and NAT are not configured");
                                    }
                                    settings = Some(s);
                                    endpoint = Some(e);
                                    if args.diagnostic_only { report.add("relay.diagnostic_listen", Status::Pass, "Authenticated diagnostic service ready; tunnel and fetch unavailable; stop with SIGINT/SIGTERM"); }
                                }
                                Err(_) => report.add("relay.diagnostic_listen", Status::Fail, "cannot initialize authenticated QUIC endpoint or bind configured UDP socket"),
                            }
                        }
                    }
                }
            }
            if !args.check_config
                && !args.diagnostic_only
                && !args.fetch
                && (!args.tunnel || !cfg!(target_os = "linux"))
            {
                report.add(
                    "relay.serve",
                    Status::Blocked,
                    "choose --diagnostic-only, --fetch, or --tunnel on a dedicated Linux relay",
                );
            }
            if args.tunnel && !cfg!(target_os = "linux") {
                report.add(
                    "relay.tunnel",
                    Status::Blocked,
                    "tunnel service requires a dedicated Linux relay",
                );
            }
        }
    }
    if report.emit(args.report.as_deref()).is_err() {
        eprintln!("FAIL report.write: cannot write new report file");
        return ExitCode::from(1);
    }
    if let (Some(endpoint), Some(settings)) = (endpoint, settings) {
        quic::serve_with_tunnel(endpoint, settings, tunnel, shutdown()).await;
    }
    ExitCode::from(report.exit_code())
}
