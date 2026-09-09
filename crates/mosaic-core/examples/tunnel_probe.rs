use anyhow::{Context, Result, ensure};
use mosaic_core::{
    config::ClientConfig,
    packet::{self, Address},
    quic,
    report::{Report, Status},
    session,
};
use std::{net::Ipv4Addr, path::Path, time::Duration};

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in bytes.chunks(2) {
        sum += u32::from(chunk[0]) * 256 + u32::from(*chunk.get(1).unwrap_or(&0));
    }
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}

fn request(source: Ipv4Addr, destination: Ipv4Addr) -> Vec<u8> {
    let mut bytes = vec![0; 44];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&44u16.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 1;
    bytes[12..16].copy_from_slice(&source.octets());
    bytes[16..20].copy_from_slice(&destination.octets());
    bytes[20] = 8;
    bytes[24..28].copy_from_slice(&[0x4d, 0x53, 0, 1]);
    bytes[28..].copy_from_slice(b"mosaic-ip-check!");
    let sum = checksum(&bytes[20..]);
    bytes[22..24].copy_from_slice(&sum.to_be_bytes());
    let sum = checksum(&bytes[..20]);
    bytes[10..12].copy_from_slice(&sum.to_be_bytes());
    bytes
}

async fn run(path: &Path) -> Result<()> {
    let config = ClientConfig::load(path)?;
    config.check_credentials()?;
    let tunnel = config
        .tunnel
        .as_ref()
        .context("isolated configuration required")?;
    let address: Ipv4Addr = tunnel
        .address
        .split_once('/')
        .context("invalid address")?
        .0
        .parse()?;
    let client = quic::connect(&config).await?;
    session::authorize_tunnel(&client.connection, &config).await?;
    tokio::time::sleep(Duration::from_millis(250)).await;
    client.connection.send_datagram(vec![0; 12].into())?;
    let spoof = Ipv4Addr::new(10, 77, 0, 99);
    client.connection.send_datagram(
        packet::encode(1, &request(spoof, tunnel.peer), Address::Source(spoof))?.into(),
    )?;
    let payload = request(address, tunnel.peer);
    let mut malformed = packet::encode(2, &payload, Address::Source(address))?;
    malformed[3] ^= 1;
    client.connection.send_datagram(malformed.into())?;
    ensure!(
        tokio::time::timeout(
            Duration::from_millis(500),
            client.connection.read_datagram()
        )
        .await
        .is_err(),
        "invalid fixture produced a reply"
    );
    client
        .connection
        .send_datagram(packet::encode(3, &payload, Address::Source(address))?.into())?;
    let bytes =
        tokio::time::timeout(Duration::from_secs(5), client.connection.read_datagram()).await??;
    let (_, reply) = packet::decode(&bytes, Address::Destination(address))?;
    ensure!(
        reply.len() == payload.len()
            && reply[9] == 1
            && reply[20] == 0
            && reply[24..] == payload[24..]
            && checksum(&reply[20..]) == 0,
        "ICMP reply mismatch"
    );
    client
        .connection
        .close(0u32.into(), b"packet validation complete");
    Ok(())
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let mut report = Report::new("live-ip-packet-validation");
    report.check_level = 3;
    let path = std::env::args().nth(1);
    let result = match path {
        Some(path) => run(Path::new(&path)).await,
        None => Err(anyhow::anyhow!("configuration path required")),
    };
    match result {
        Ok(()) => report.add("tunnel.invalid_then_valid", Status::Pass, "malformed and spoofed fixtures produced no reply; subsequent valid ICMP reply matched; verify receiving TUN capture separately"),
        Err(_) => report.add("tunnel.invalid_then_valid", Status::Fail, "packet validation failed or exceeded deadline"),
    }
    if report.emit(None).is_err() {
        return std::process::ExitCode::from(1);
    }
    std::process::ExitCode::from(report.exit_code())
}
