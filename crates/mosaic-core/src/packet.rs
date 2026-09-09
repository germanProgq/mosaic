use crate::frame::{self, MTU, PACKET_HEADER_BYTES, VERSION};
use anyhow::{Result, ensure};
use std::net::Ipv4Addr;

pub const IPV4: u8 = 2;

#[derive(Clone, Copy)]
pub enum Address {
    Source(Ipv4Addr),
    Destination(Ipv4Addr),
}

pub fn validate(bytes: &[u8], address: Address) -> Result<()> {
    ensure!(
        (20..=MTU).contains(&bytes.len()),
        "invalid IPv4 packet size"
    );
    ensure!(bytes[0] >> 4 == 4, "only IPv4 packets are supported");
    let header = usize::from(bytes[0] & 15) * 4;
    ensure!(
        header >= 20 && header <= bytes.len(),
        "invalid IPv4 header length"
    );
    ensure!(
        usize::from(u16::from_be_bytes([bytes[2], bytes[3]])) == bytes.len(),
        "IPv4 length mismatch"
    );
    let sum: u32 = bytes[..header]
        .chunks_exact(2)
        .map(|b| u32::from(u16::from_be_bytes([b[0], b[1]])))
        .sum();
    let sum = (sum & 0xffff) + (sum >> 16);
    ensure!(
        (sum & 0xffff) + (sum >> 16) == 0xffff,
        "invalid IPv4 header checksum"
    );
    let fragment = u16::from_be_bytes([bytes[6], bytes[7]]);
    ensure!(fragment & 0x8000 == 0, "reserved IPv4 flag");
    ensure!(
        fragment & 0x4000 == 0 || fragment & 0x3fff == 0,
        "invalid IPv4 fragment flags"
    );
    if fragment & 0x2000 != 0 {
        ensure!(
            bytes.len() > header && (bytes.len() - header).is_multiple_of(8),
            "invalid IPv4 fragment length"
        );
    }
    ensure!(
        usize::from(fragment & 0x1fff) * 8 + bytes.len() - header <= 65515,
        "IPv4 fragment exceeds packet limit"
    );
    let (offset, expected) = match address {
        Address::Source(ip) => (12, ip),
        Address::Destination(ip) => (16, ip),
    };
    ensure!(
        bytes[offset..offset + 4] == expected.octets(),
        "IPv4 address rejected"
    );
    Ok(())
}

pub fn encode(sequence: u64, payload: &[u8], address: Address) -> Result<Vec<u8>> {
    validate(payload, address)?;
    let mut bytes = frame::packet(sequence, payload)?;
    bytes[1] = IPV4;
    Ok(bytes)
}

pub fn decode(bytes: &[u8], address: Address) -> Result<(u64, &[u8])> {
    ensure!(
        (PACKET_HEADER_BYTES + 20..=PACKET_HEADER_BYTES + MTU).contains(&bytes.len()),
        "invalid IP datagram size"
    );
    ensure!(
        bytes[0] == VERSION && bytes[1] == IPV4,
        "unsupported IP datagram version or kind"
    );
    ensure!(
        usize::from(u16::from_be_bytes([bytes[2], bytes[3]])) == bytes.len() - PACKET_HEADER_BYTES,
        "IP datagram length mismatch"
    );
    let sequence = u64::from_be_bytes(bytes[4..12].try_into()?);
    let payload = &bytes[PACKET_HEADER_BYTES..];
    validate(payload, address)?;
    Ok((sequence, payload))
}
