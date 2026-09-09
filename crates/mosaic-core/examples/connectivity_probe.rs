use mosaic_core::{config::ClientConfig, quic};
use std::{path::Path, process::ExitCode, time::Instant};

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let result = run(&args).await;
    match result {
        Ok(value) => {
            println!("{value}");
            ExitCode::SUCCESS
        }
        Err(_) => {
            println!("{{\"status\":\"FAIL\",\"id\":\"live_probe\"}}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: &[String]) -> anyhow::Result<serde_json::Value> {
    anyhow::ensure!(args.len() >= 3, "arguments");
    let mut config = ClientConfig::load(Path::new(&args[1]))?;
    config.check_credentials()?;
    let case = args[2].as_str();
    match case {
        "handshake" => {}
        "wrong-name" => config.server.name = "wrong-identity.invalid".into(),
        "wrong-alpn" => config.transport.alpn = "mosaic-invalid/2".into(),
        "wrong-trust" => {
            anyhow::ensure!(args.len() == 4, "trust fixture required");
            config.tls.trust_cert = args[3].clone().into();
        }
        _ => anyhow::bail!("unknown case"),
    }
    let started = Instant::now();
    let connection = quic::connect(&config).await;
    let elapsed = started.elapsed();
    if case == "handshake" {
        let client = connection?;
        mosaic_core::session::authorize(&client.connection, &config).await?;
        quic::echo(&client.connection, b"live QUIC reachability").await?;
    } else {
        let error = connection
            .err()
            .ok_or_else(|| anyhow::anyhow!("invalid identity accepted"))?;
        anyhow::ensure!(elapsed < quic::CONNECT_DEADLINE, "late rejection");
        anyhow::ensure!(
            matches!(
                error.downcast_ref::<quinn::ConnectionError>(),
                Some(quinn::ConnectionError::TransportError(_))
                    | Some(quinn::ConnectionError::ConnectionClosed(_))
            ),
            "not a TLS rejection"
        );
    }
    Ok(serde_json::json!({"status":"PASS","id":case,"handshake_ms":elapsed.as_secs_f64()*1000.0}))
}
