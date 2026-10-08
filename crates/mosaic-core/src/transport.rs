use crate::{frame, session::SizeError};
use anyhow::{Result, bail, ensure};
use std::future::Future;

#[derive(Debug)]
pub struct PacketTooLarge;

impl std::fmt::Display for PacketTooLarge {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str("packet exceeds the current transport packet size")
    }
}

impl std::error::Error for PacketTooLarge {}

pub trait PacketTransport: Send + Sync {
    fn max_packet_size(&self) -> Option<usize>;
    fn send_packet(&self, bytes: Vec<u8>) -> impl Future<Output = Result<()>> + Send;
    fn receive_packet(&self) -> impl Future<Output = Result<Vec<u8>>> + Send;
    fn stream_opened(&self) -> impl Future<Output = Result<()>> + Send;
    fn close(&self, code: u32, reason: &[u8]);
}

pub fn checked_size(size: Option<usize>) -> Result<usize> {
    let size = size.ok_or(SizeError)?;
    ensure!(size >= frame::MTU + frame::PACKET_HEADER_BYTES, SizeError);
    Ok(size)
}

impl PacketTransport for quinn::Connection {
    fn max_packet_size(&self) -> Option<usize> {
        self.max_datagram_size()
    }

    async fn send_packet(&self, bytes: Vec<u8>) -> Result<()> {
        let limit = checked_size(self.max_packet_size())?;
        ensure!(bytes.len() <= limit, PacketTooLarge);
        match self.send_datagram_wait(bytes.into()).await {
            Ok(()) => Ok(()),
            Err(quinn::SendDatagramError::TooLarge) => Err(PacketTooLarge.into()),
            Err(error) => Err(error.into()),
        }
    }

    async fn receive_packet(&self) -> Result<Vec<u8>> {
        Ok(self.read_datagram().await?.to_vec())
    }

    async fn stream_opened(&self) -> Result<()> {
        match self.accept_bi().await {
            Err(error) => Err(error.into()),
            Ok(_) => bail!("streams are unavailable in tunnel mode"),
        }
    }

    fn close(&self, code: u32, reason: &[u8]) {
        quinn::Connection::close(self, code.into(), reason);
    }
}
