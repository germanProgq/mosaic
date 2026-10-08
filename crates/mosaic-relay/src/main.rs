use clap::Parser;
use mosaic_core::{
    config::RelayConfig,
    quic,
    report::{Report, Status},
    session,
};
use std::{path::PathBuf, process::ExitCode};
#[cfg(target_os = "linux")]
mod forwarding;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod rules;
#[cfg(target_os = "linux")]
mod setup;
#[cfg(target_os = "linux")]
mod system;
#[derive(Parser)]
#[command(
    version,
    about = "Mosaic relay — configuration validation and authenticated diagnostics"
)]
struct Cli {
    #[arg(short, long, required_unless_present = "uninstall")]
    config: Option<PathBuf>,
    #[arg(long, conflicts_with_all = ["check_config", "diagnostic_only", "tunnel", "fetch", "uninstall"])]
    setup: bool,
    #[arg(long, conflicts_with_all = ["check_config", "diagnostic_only", "tunnel", "fetch"])]
    uninstall: bool,
    #[arg(long, requires = "tunnel")]
    forwarding: bool,
    #[arg(long, conflicts_with_all = ["diagnostic_only", "check_config"])]
    proxy: bool,
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

fn administer(args: &Cli) -> ExitCode {
    let mut report = Report::new("relay-installation");
    let name = if args.setup {
        "relay.setup"
    } else {
        "relay.uninstall"
    };
    #[cfg(target_os = "linux")]
    {
        let result = if args.setup {
            setup::setup(
                args.config
                    .as_deref()
                    .expect("required by the command line"),
            )
        } else {
            setup::uninstall()
        };
        match result {
            Ok(()) if args.setup => report.add(
                name,
                Status::Pass,
                "relay installed; mosaic-relay.service runs the tunnel with owned forwarding",
            ),
            Ok(()) => report.add(
                name,
                Status::Pass,
                "owned relay service, files and forwarding removed",
            ),
            Err(error) => report.add(name, Status::Fail, &format!("{error:#}")),
        }
    }
    #[cfg(not(target_os = "linux"))]
    report.add(
        name,
        Status::Blocked,
        "relay installation requires a dedicated Linux host",
    );
    if report.emit(args.report.as_deref()).is_err() {
        eprintln!("FAIL report.write: cannot write new report file");
        return ExitCode::from(1);
    }
    ExitCode::from(report.exit_code())
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Cli::parse();
    if args.setup || args.uninstall {
        return administer(&args);
    }
    let config_path = args.config.clone().expect("required by the command line");
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
    let mut client = None;
    match RelayConfig::load(&config_path) {
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
                        if (args.diagnostic_only || args.fetch || args.tunnel || args.proxy)
                            && (!args.tunnel || cfg!(target_os = "linux"))
                        {
                            match session::Settings::load(&c).and_then(|s| quic::relay_endpoint(&c).map(|e| (e, s))) {
                                Ok((e, mut s)) => {
                                    if args.proxy {
                                        s.enable_proxy();
                                        report.add("relay.proxy_listen", Status::Pass, "Authenticated proxy service ready; public IPv4 TCP destinations only; relay networks and port 25 refused");
                                    }
                                    if args.fetch {
                                        s.enable_fetch(c.fetch);
                                        report.check_level = 4;
                                        report.scope = "fetch-service".into();
                                        report.add("relay.fetch_listen", Status::Pass, "Authenticated allowlisted TCP service ready; bounded IPv4 HTTPS forwarding; no TUN egress assertion");
                                    }
                                    if args.tunnel {
                                        client = Some(c.allowed_client);
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
                && !args.proxy
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
    #[cfg(target_os = "linux")]
    let mut forwarding = None;
    #[cfg(target_os = "linux")]
    if args.forwarding
        && endpoint.is_some()
        && let (Some(t), Some(client)) = (tunnel.as_ref(), client)
    {
        let directory = std::path::Path::new("/var/lib/mosaic-relay");
        match forwarding::Forwarding::up(directory, &t.name, client) {
            Ok(owned) => {
                report.add(
                    "relay.forwarding",
                    Status::Pass,
                    "owned IPv4 forwarding and NAT installed for the tunnel client",
                );
                forwarding = Some(owned);
            }
            Err(error) => {
                report.add("relay.forwarding", Status::Fail, &format!("{error:#}"));
                endpoint = None;
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = client;
    if report.emit(args.report.as_deref()).is_err() {
        eprintln!("FAIL report.write: cannot write new report file");
        #[cfg(target_os = "linux")]
        if let Some(owned) = forwarding {
            let _ = owned.down();
        }
        return ExitCode::from(1);
    }
    if let (Some(endpoint), Some(settings)) = (endpoint, settings) {
        quic::serve_with_tunnel(endpoint, settings, tunnel, shutdown()).await;
    }
    #[cfg(target_os = "linux")]
    if let Some(owned) = forwarding
        && let Err(error) = owned.down()
    {
        eprintln!("FAIL relay.forwarding_cleanup: {error:#}");
        return ExitCode::from(1);
    }
    ExitCode::from(report.exit_code())
}
