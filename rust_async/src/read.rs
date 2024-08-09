use byteorder::ByteOrder;
use tokio::io::{AsyncRead, AsyncReadExt, BufReader, Take};

use async_compression::tokio::bufread::ZstdDecoder;
use mcap::{McapError, McapResult, MAGIC};

enum ReaderState<R> {
    Base(R),
    UncompressedChunk(Take<R>),
    ZstdChunk(ZstdDecoder<BufReader<Take<R>>>),
    Empty,
}

impl<R> AsyncRead for ReaderState<R>
where
    R: AsyncRead + std::marker::Unpin,
{
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            ReaderState::Base(r) => std::pin::pin!(r).poll_read(cx, buf),
            ReaderState::UncompressedChunk(r) => std::pin::pin!(r).poll_read(cx, buf),
            ReaderState::ZstdChunk(r) => std::pin::pin!(r).poll_read(cx, buf),
            ReaderState::Empty => {
                panic!("invariant: reader is only set to empty while swapping with another valid variant")
            }
        }
    }
}
impl<R> ReaderState<R>
where
    R: AsyncRead,
{
    pub fn into_inner(self) -> R {
        match self {
            ReaderState::Base(reader) => reader,
            ReaderState::UncompressedChunk(take) => take.into_inner(),
            ReaderState::ZstdChunk(decoder) => decoder.into_inner().into_inner().into_inner(),
            ReaderState::Empty => {
                panic!("invariant: reader is only set to empty while swapping with another valid variant")
            }
        }
    }
}
pub struct LinearReader<R> {
    reader: ReaderState<R>,
    options: Options,
    start_magic_seen: bool,
    footer_seen: bool,
    scratch: [u8; 9],
}

#[derive(Default, Clone)]
pub struct Options {
    skip_start_magic: bool,
    skip_end_magic: bool,
    emit_chunks: bool,
}

/// Internal
enum Cmd {
    YieldRecord(u8),
    EnterChunk(mcap::records::ChunkHeader),
    ExitChunk,
    Stop,
}
impl<R> LinearReader<R>
where
    R: AsyncRead + std::marker::Unpin,
{
    pub fn new(reader: R) -> Self {
        Self::new_with_options(reader, &Options::default())
    }

    pub fn new_with_options(reader: R, options: &Options) -> Self {
        Self {
            reader: ReaderState::Base(reader),
            options: options.clone(),
            start_magic_seen: false,
            footer_seen: false,
            scratch: [0; 9],
        }
    }

    pub fn into_inner(self) -> R {
        self.reader.into_inner()
    }

    pub async fn next_record(&mut self, data: &mut Vec<u8>) -> McapResult<Option<u8>> {
        loop {
            let cmd = self.next_record_inner(data).await?;
            match cmd {
                Cmd::Stop => return Ok(None),
                Cmd::YieldRecord(opcode) => return Ok(Some(opcode)),
                Cmd::EnterChunk(header) => {
                    let mut rdr = ReaderState::Empty;
                    std::mem::swap(&mut rdr, &mut self.reader);
                    match header.compression.as_str() {
                        "zstd" => {
                            self.reader = ReaderState::ZstdChunk(ZstdDecoder::new(BufReader::new(
                                rdr.into_inner().take(header.compressed_size),
                            )));
                        }
                        "" => {
                            self.reader = ReaderState::UncompressedChunk(
                                rdr.into_inner().take(header.compressed_size),
                            );
                        }
                        _ => {
                            std::mem::swap(&mut rdr, &mut self.reader);
                            return Err(McapError::UnsupportedCompression(
                                header.compression.clone(),
                            ));
                        }
                    }
                }
                Cmd::ExitChunk => {
                    let mut rdr = ReaderState::Empty;
                    std::mem::swap(&mut rdr, &mut self.reader);
                    self.reader = ReaderState::Base(rdr.into_inner())
                }
            };
        }
    }

    async fn next_record_inner(&mut self, data: &mut Vec<u8>) -> McapResult<Cmd> {
        if let ReaderState::Base(reader) = &mut self.reader {
            if !self.start_magic_seen && !self.options.skip_start_magic {
                reader.read_exact(&mut self.scratch[..MAGIC.len()]).await?;
                if &self.scratch[..MAGIC.len()] != MAGIC {
                    return Err(McapError::BadMagic);
                }
                self.start_magic_seen = true;
            }
            if self.footer_seen && !self.options.skip_end_magic {
                reader.read_exact(&mut self.scratch[..MAGIC.len()]).await?;
                if &self.scratch[..MAGIC.len()] != MAGIC {
                    return Err(McapError::BadMagic);
                }
                return Ok(Cmd::Stop);
            }
            reader.read_exact(&mut self.scratch).await?;
            let opcode = self.scratch[0];
            if opcode == mcap::records::op::FOOTER {
                self.footer_seen = true;
            }
            let record_len = byteorder::LittleEndian::read_u64(&self.scratch[1..]);
            if opcode == mcap::records::op::CHUNK && !self.options.emit_chunks {
                let chunk_header = read_chunk_header(reader, data, record_len).await?;
                return Ok(Cmd::EnterChunk(chunk_header));
            }
            data.resize(record_len as usize, 0);
            reader.read_exact(&mut data[..]).await?;
            Ok(Cmd::YieldRecord(opcode))
        } else {
            let len = self.reader.read(&mut self.scratch).await?;
            if len == 0 {
                return Ok(Cmd::ExitChunk);
            }
            if len != self.scratch.len() {
                return Err(McapError::UnexpectedEof);
            }
            let opcode = self.scratch[0];
            let record_len = byteorder::LittleEndian::read_u64(&self.scratch[1..]);
            data.resize(record_len as usize, 0);
            self.reader.read_exact(&mut data[..]).await?;
            Ok(Cmd::YieldRecord(opcode))
        }
    }
}

async fn read_chunk_header<R: AsyncRead + std::marker::Unpin>(
    reader: &mut R,
    scratch: &mut Vec<u8>,
    record_len: u64,
) -> McapResult<mcap::records::ChunkHeader> {
    let mut header = mcap::records::ChunkHeader {
        message_start_time: 0,
        message_end_time: 0,
        uncompressed_size: 0,
        uncompressed_crc: 0,
        compression: String::new(),
        compressed_size: 0,
    };
    scratch.resize(32, 0);
    reader.read_exact(&mut scratch[..]).await?;
    header.message_start_time = byteorder::LittleEndian::read_u64(&scratch[0..8]);
    header.message_end_time = byteorder::LittleEndian::read_u64(&scratch[8..16]);
    header.uncompressed_size = byteorder::LittleEndian::read_u64(&scratch[16..24]);
    header.uncompressed_crc = byteorder::LittleEndian::read_u32(&scratch[24..28]);
    let compression_len = byteorder::LittleEndian::read_u32(&scratch[28..32]);
    scratch.resize(compression_len as usize, 0);
    reader.read_exact(&mut scratch[..]).await?;
    header.compression = match std::str::from_utf8(&scratch[..]) {
        Ok(val) => val.to_owned(),
        Err(err) => {
            return Err(McapError::Parse(binrw::error::Error::Custom { pos: 32, err: Box::new(err) }));
        }
    };
    scratch.resize(8, 0);
    reader.read_exact(&mut scratch[..]).await?;
    header.compressed_size = byteorder::LittleEndian::read_u64(&scratch[..]);
    let available = record_len - (32 + compression_len as u64 + 8);
    if available < header.compressed_size {
        return Err(McapError::BadChunkLength { header: header.compressed_size , available });
    }
    Ok(header)
}


#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    #[tokio::test]
    async fn test_base_reads() -> Result<(), mcap::McapError> {
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut writer = mcap::Writer::new(&mut buf)?;
            writer.finish()?;
        }
        let mut reader = LinearReader::new(std::io::Cursor::new(buf.into_inner()));
        let mut record: Vec<u8> = Vec::new();
        let mut opcodes: Vec<u8> = Vec::new();
        loop {
            let opcode = reader.next_record(&mut record).await?;
            if let Some(opcode) = opcode {
                opcodes.push(opcode);
            } else {
                break;
            }
        }
        assert_eq!(
            opcodes.as_slice(),
            [
                mcap::records::op::HEADER,
                mcap::records::op::DATA_END,
                mcap::records::op::STATISTICS,
                mcap::records::op::SUMMARY_OFFSET,
                mcap::records::op::FOOTER,
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_reads_zstd_chunk() -> Result<(), mcap::McapError> {
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut writer = mcap::Writer::new(&mut buf)?;
            let channel = std::sync::Arc::new(mcap::Channel {
                topic: "chat".to_owned(),
                schema: None,
                message_encoding: "json".to_owned(),
                metadata: BTreeMap::new(),
            });
            writer.add_channel(&channel)?;
            writer.write(&mcap::Message {
                channel,
                sequence: 0,
                log_time: 0,
                publish_time: 0,
                data: (&[0, 1, 2]).into(),
            })?;
            writer.finish()?;
        }
        let mut reader = LinearReader::new(std::io::Cursor::new(buf.into_inner()));
        let mut record = Vec::new();
        let mut opcodes: Vec<u8> = Vec::new();
        loop {
            let opcode = reader.next_record(&mut record).await?;
            if let Some(opcode) = opcode {
                opcodes.push(opcode);
            } else {
                break;
            }
        }
        assert_eq!(
            opcodes.as_slice(),
            [
                mcap::records::op::HEADER,
                mcap::records::op::CHANNEL,
                mcap::records::op::MESSAGE,
                mcap::records::op::MESSAGE_INDEX,
                mcap::records::op::DATA_END,
                mcap::records::op::CHANNEL,
                mcap::records::op::CHUNK_INDEX,
                mcap::records::op::STATISTICS,
                mcap::records::op::SUMMARY_OFFSET,
                mcap::records::op::SUMMARY_OFFSET,
                mcap::records::op::SUMMARY_OFFSET,
                mcap::records::op::FOOTER,
            ]
        );
        Ok(())
    }
    #[tokio::test]
    async fn test_reads_uncompressed_chunk() -> Result<(), mcap::McapError> {
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut writer = mcap::WriteOptions::new()
                .compression(None)
                .create(&mut buf)?;
            let channel = std::sync::Arc::new(mcap::Channel {
                topic: "chat".to_owned(),
                schema: None,
                message_encoding: "json".to_owned(),
                metadata: BTreeMap::new(),
            });
            writer.add_channel(&channel)?;
            writer.write(&mcap::Message {
                channel,
                sequence: 0,
                log_time: 0,
                publish_time: 0,
                data: (&[0, 1, 2]).into(),
            })?;
            writer.finish()?;
        }
        let mut reader = LinearReader::new(std::io::Cursor::new(buf.into_inner()));
        let mut record = Vec::new();
        let mut opcodes: Vec<u8> = Vec::new();
        loop {
            let opcode = reader.next_record(&mut record).await?;
            if let Some(opcode) = opcode {
                opcodes.push(opcode);
            } else {
                break;
            }
        }
        assert_eq!(
            opcodes.as_slice(),
            [
                mcap::records::op::HEADER,
                mcap::records::op::CHANNEL,
                mcap::records::op::MESSAGE,
                mcap::records::op::MESSAGE_INDEX,
                mcap::records::op::DATA_END,
                mcap::records::op::CHANNEL,
                mcap::records::op::CHUNK_INDEX,
                mcap::records::op::STATISTICS,
                mcap::records::op::SUMMARY_OFFSET,
                mcap::records::op::SUMMARY_OFFSET,
                mcap::records::op::SUMMARY_OFFSET,
                mcap::records::op::FOOTER,
            ]
        );
        Ok(())
    }
}
