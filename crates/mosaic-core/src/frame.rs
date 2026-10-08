use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

pub const MAX_CONTROL_BYTES: usize = 4096;
pub const MAX_QUEUE_PACKETS: usize = 2048;
pub const DATAGRAM_BUFFER_BYTES: usize = 2 * 1024 * 1024;
pub const DATAGRAM_SEND_BUFFER_BYTES: usize = 512 * 1024;
pub const DIAGNOSTIC_QUEUE_PACKETS: usize = 256;
pub const PACKET_HEADER_BYTES: usize = 12;
pub const MTU: usize = 1100;
pub const VERSION: u8 = 2;
pub const DIAGNOSTIC: u8 = 1;

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum Control {
    SessionInit {
        version: u8,
        mode: String,
        token: String,
        mtu: usize,
        send_limit: usize,
    },
    SessionReady {
        version: u8,
        mode: String,
        mtu: usize,
        send_limit: usize,
        session_id: String,
    },
    ClientReady {
        version: u8,
        mode: String,
        mtu: usize,
        send_limit: usize,
        session_id: String,
    },
}

pub async fn read_control<T: DeserializeOwned>(
    recv: &mut quinn::RecvStream,
    limit: usize,
) -> Result<T> {
    let mut header = [0; 4];
    recv.read_exact(&mut header).await?;
    let length = u32::from_be_bytes(header) as usize;
    ensure!(
        length > 0 && length <= limit.min(MAX_CONTROL_BYTES),
        "invalid control length"
    );
    let mut bytes = vec![0; length];
    recv.read_exact(&mut bytes).await?;
    serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid control message"))
}

pub async fn write_control<T: Serialize>(
    send: &mut quinn::SendStream,
    message: &T,
    limit: usize,
) -> Result<()> {
    let bytes =
        serde_json::to_vec(message).map_err(|_| anyhow::anyhow!("invalid control message"))?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= limit.min(MAX_CONTROL_BYTES),
        "invalid control length"
    );
    send.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    send.write_all(&bytes).await?;
    Ok(())
}

pub async fn finish_control(recv: &mut quinn::RecvStream) -> Result<()> {
    let mut extra = [0];
    ensure!(
        recv.read(&mut extra).await?.is_none(),
        "unexpected control data"
    );
    Ok(())
}

pub fn packet(sequence: u64, payload: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        !payload.is_empty() && payload.len() <= MTU,
        "invalid packet size"
    );
    let mut bytes = Vec::with_capacity(PACKET_HEADER_BYTES + payload.len());
    bytes.extend_from_slice(&[VERSION, DIAGNOSTIC]);
    bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

pub fn read_packet(bytes: &[u8]) -> Result<(u64, &[u8])> {
    ensure!(
        (PACKET_HEADER_BYTES + 1..=PACKET_HEADER_BYTES + MTU).contains(&bytes.len()),
        "invalid packet size"
    );
    ensure!(
        bytes[0] == VERSION && bytes[1] == DIAGNOSTIC,
        "unsupported packet version or kind"
    );
    let length = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    ensure!(
        length == bytes.len() - PACKET_HEADER_BYTES,
        "packet length mismatch"
    );
    let mut sequence = [0; 8];
    sequence.copy_from_slice(&bytes[4..12]);
    Ok((u64::from_be_bytes(sequence), &bytes[PACKET_HEADER_BYTES..]))
}
