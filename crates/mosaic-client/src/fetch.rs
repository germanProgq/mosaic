use mosaic_core::{
    config::{ClientConfig, read_bounded},
    fetch,
    report::{Report, Status},
};
use std::{path::Path, process::ExitCode};

pub async fn run(
    config: &Path,
    url: &str,
    upload: Option<&Path>,
    expected: Option<&str>,
    output: Option<&Path>,
) -> ExitCode {
    let mut report = Report::new("native-fetch");
    report.check_level = 4;
    report.add(
        "fetch.scope",
        Status::Pass,
        "HTTPS from this process only; ordinary browser and application traffic, system routing and DNS are unchanged; this is not a desktop VPN connection",
    );
    let work = async {
        let config = ClientConfig::load(config)?;
        config.check_credentials()?;
        fetch::target(url)?;
        if let Some(hash) = expected {
            anyhow::ensure!(
                hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()),
                "invalid expected hash"
            );
        }
        let upload = upload
            .map(|path| read_bounded(path, fetch::MAX_UPLOAD_BYTES, false))
            .transpose()?;
        fetch::run(&config, url, upload).await
    }
    .await;
    match work {
        Ok(outcome) => {
            report.add("fetch.https", Status::Pass, &format!("verified HTTPS through authenticated relay TCP; status {}; received {} bytes; SHA-256 {}", outcome.status, outcome.bytes, outcome.sha256));
            if upload.is_some() {
                report.add("fetch.upload", Status::Pass, &format!("sent {} bytes; SHA-256 {}; remote integrity requires the destination's independent receipt", outcome.uploaded_bytes, outcome.upload_sha256));
            }
            if let Some(expected) = expected {
                report.add("fetch.integrity", if expected.eq_ignore_ascii_case(&outcome.sha256) { Status::Pass } else { Status::Fail }, "response SHA-256 compared with expected value");
            }
            if let Some(ip) = outcome.egress {
                report.add("fetch.egress", Status::Pass, &format!("HTTPS service observed {ip}; compare with independently measured relay egress"));
            }
        }
        Err(_) => report.add("fetch.https", Status::Fail, "configuration, authorization, allowed destination, verified HTTPS, transfer limit or deadline failed"),
    }
    if report.emit(output).is_err() {
        eprintln!("FAIL report.write: cannot write new report file");
        return ExitCode::from(1);
    }
    ExitCode::from(report.exit_code())
}
