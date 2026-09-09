use serde::Serialize;
use std::{
    fs::OpenOptions,
    io::Write,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Status {
    Pass,
    Fail,
    Blocked,
}
#[derive(Serialize)]
pub struct Assertion {
    pub id: String,
    pub status: Status,
    pub detail: String,
}
#[derive(Serialize)]
pub struct Report {
    pub schema_version: u8,
    pub check_level: u8,
    pub scope: String,
    pub status: Status,
    pub unix_time: u64,
    pub os: String,
    pub arch: String,
    pub assertions: Vec<Assertion>,
}
impl Report {
    pub fn new(scope: &str) -> Self {
        Self {
            schema_version: 1,
            check_level: 0,
            scope: scope.into(),
            status: Status::Pass,
            unix_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            os: std::env::consts::OS.into(),
            arch: std::env::consts::ARCH.into(),
            assertions: vec![],
        }
    }
    pub fn add(&mut self, id: &str, status: Status, detail: &str) {
        if status == Status::Fail || (status == Status::Blocked && self.status == Status::Pass) {
            self.status = status;
        }
        self.assertions.push(Assertion {
            id: id.into(),
            status,
            detail: detail.into(),
        });
    }
    pub fn emit(&self, path: Option<&Path>) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        if let Some(path) = path {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(path).map_err(|_| {
                anyhow::anyhow!("cannot create report (parent must exist; file must be new)")
            })?;
            file.write_all(json.as_bytes())?;
            file.write_all(b"\n")?;
        }
        println!("{json}");
        Ok(())
    }
    pub fn exit_code(&self) -> u8 {
        match self.status {
            Status::Pass => 0,
            Status::Fail => 1,
            Status::Blocked => 2,
        }
    }
}
