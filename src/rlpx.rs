use crate::handshake::SessionSecrets;
use crate::mac;
use byteorder::{BigEndian, ByteOrder, ReadBytesExt};
use cipher::StreamCipher;
use futures::{SinkExt, TryStreamExt};
use rlp::{Decodable, Encodable, RlpDecodable, RlpEncodable, RlpStream};
use std::io;
use tokio::net::TcpStream;
use tokio_util::codec::{Decoder, Encoder};
use tracing::info;

pub const ETH_66: usize = 66;
pub const ETH_67: usize = 67;
pub const ETH_68: usize = 68;

/// Header size + MAC size
const HEADER_SIZE: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum RlpxError {
    #[error("IO error")]
    IO(#[from] io::Error),
    #[error("secp256k1 error - `{0:?}`")]
    Secp256k1(#[from] secp256k1::Error),
    #[error("tag check failure")]
    TagDecryptFailed,
    #[error("invalid RLP")]
    InvalidRlp(#[from] rlp::DecoderError),
    #[error("Stream has been closed")]
    StreamClosed,
    #[error("Invalid size")]
    FromInt(#[from] std::num::TryFromIntError),
    #[error("Unexpected message received")]
    UnexpectedMessage,
}

pub struct Rlpx {
    ingress_aes: ctr::Ctr64BE<aes::Aes256>,
    egress_aes: ctr::Ctr64BE<aes::Aes256>,
    ingress_mac: mac::MacState,
    egress_mac: mac::MacState,
    state: RlpxState,
}

impl Rlpx {
    pub fn new(secrets: SessionSecrets) -> Self {
        Self {
            ingress_aes: secrets.ingress_aes,
            egress_aes: secrets.egress_aes,
            ingress_mac: secrets.ingress_mac,
            egress_mac: secrets.egress_mac,
            state: RlpxState::Header,
        }
    }

    /// Writes `header-ciphertext || header-mac`
    ///
    /// header = frame-size || header-data || header-padding
    ///
    /// header-ciphertext = aes(aes-secret, header)
    ///
    /// frame-size = length of frame-data, encoded as a 24bit big-endian integer
    /// header-data = [capability-id, context-id], always [0, 0] rlp
    /// capability-id = integer, always zero
    /// context-id = integer, always zero
    /// header-padding = zero-fill header to 16-byte boundary
    ///
    /// Basically it is 3 bytes for length, 3 bytes for hardcoded RLP (header data) and
    /// remaining 10 bytes as padding. In addition to it we also write a MAC,
    /// consisting of 16 bytes. In total - 32 bytes.
    fn write_header(&mut self, dst: &mut bytes::BytesMut, data_size: usize) {
        dst.reserve(HEADER_SIZE); // header len (header + MAC)
        let mut header = [0u8; 16];
        // First write 3 bytes as length
        BigEndian::write_uint(&mut header[..], data_size as u64, 3);
        header[3..6].copy_from_slice(&[194, 128, 128]); // [0, 0] in RLP
        self.egress_aes.apply_keystream(&mut header);
        self.egress_mac.update_header(&header);
        let tag = self.egress_mac.digest();

        dst.extend_from_slice(&header);
        dst.extend_from_slice(&tag);
    }

    /// frame-ciphertext || frame-mac
    ///
    /// frame-ciphertext = aes(aes-secret, frame-data || frame-padding)
    /// frame-padding = zero-fill frame-data to 16-byte boundary
    fn write_body(&mut self, dst: &mut bytes::BytesMut, mut data: Vec<u8>) {
        let new_data_len = ((data.len() - 1) | 0b1111) + 1; // align to 16-byte boundary
        data.resize(new_data_len, 0);
        let frame_ciphertext = {
            self.egress_aes.apply_keystream(&mut data);
            data
        };
        self.egress_mac.update_body(&frame_ciphertext);
        let frame_mac = self.egress_mac.digest();

        dst.extend_from_slice(&frame_ciphertext);
        dst.extend_from_slice(&frame_mac);
    }

    /// Reads header, verifies MAC and returns payload size
    fn read_header(&mut self, header: &mut [u8]) -> Result<usize, RlpxError> {
        let (header, mac) = header.split_at_mut(16);
        self.ingress_mac.update_header(&header);
        if self.ingress_mac.digest() != mac {
            return Err(RlpxError::TagDecryptFailed);
        }
        self.ingress_aes.apply_keystream(header);

        let header = header.to_vec();
        let body_size = usize::try_from(header.as_slice().read_uint::<BigEndian>(3)?)?;

        Ok(body_size)
    }

    /// data = frame-ciphertext || frame-mac
    ///
    /// Returns frame plaintext
    fn read_body(&mut self, mut data: Vec<u8>) -> Result<Vec<u8>, RlpxError> {
        let split_at = data.len() - 16;
        let (frame_ciphertext, mac) = data.split_at_mut(split_at);
        self.ingress_mac.update_body(frame_ciphertext);
        if self.ingress_mac.digest() != mac {
            return Err(RlpxError::TagDecryptFailed);
        }

        self.ingress_aes.apply_keystream(frame_ciphertext);
        let decrypted = frame_ciphertext;

        Ok(decrypted.to_owned())
    }
}

#[derive(Debug, Clone, Copy)]
enum RlpxState {
    Header,
    Body(usize),
}

pub struct RlpxStream {
    io: tokio_util::codec::Framed<TcpStream, Rlpx>,
}

impl RlpxStream {
    pub fn new(io: TcpStream, secrets: SessionSecrets) -> Self {
        let rlpx = Rlpx::new(secrets);

        Self {
            io: rlpx.framed(io),
        }
    }

    pub async fn handshake(&mut self, hello_msg: Hello) -> Result<(), RlpxError> {
        let encoded = RlpxMessage::Hello(hello_msg.clone()).encode();

        info!("Sending hello message to the remote");
        self.io.send(encoded).await?;

        let msg = self.io.try_next().await?.ok_or(RlpxError::StreamClosed)?;
        let rlpx_message = RlpxMessage::decode(msg)?;
        // We expect the first message to be hello
        crate::ensure(
            matches!(rlpx_message, RlpxMessage::Hello(_)),
            RlpxError::UnexpectedMessage,
        )?;
        info!("Received hello message from the remote: {rlpx_message:?}");
        info!("Verifying capabilities");

        Ok(())
    }
}

impl Encoder<Vec<u8>> for Rlpx {
    type Error = RlpxError;

    /// frame = header-ciphertext || header-mac || frame-ciphertext || frame-mac
    fn encode(&mut self, data: Vec<u8>, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
        self.write_header(dst, data.len()); // header-ciphertext || header-mac
        self.write_body(dst, data); // frame-ciphertext || frame-mac

        Ok(())
    }
}

impl Decoder for Rlpx {
    type Item = Vec<u8>;

    type Error = RlpxError;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        loop {
            match self.state {
                RlpxState::Header => {
                    if src.len() < HEADER_SIZE {
                        return Ok(None);
                    }
                    let mut header = src.split_to(HEADER_SIZE);
                    let body_size = self.read_header(header.as_mut())?;
                    self.state = RlpxState::Body(body_size);
                }
                RlpxState::Body(data_size) => {
                    let expected_size = if data_size % 16 == 0 {
                        data_size
                    } else {
                        // align to 16 bytes + 16 byte for mac
                        (data_size | 31) + 1
                    };
                    if src.len() < expected_size {
                        return Ok(None);
                    }
                    let body_encrypted = src.split_to(expected_size).to_vec();
                    let mut body = self.read_body(body_encrypted)?;
                    // Pop padded data
                    if data_size != expected_size {
                        for _ in 0..expected_size - data_size - 16 {
                            body.pop();
                        }
                    }

                    self.state = RlpxState::Header;
                    return Ok(Some(body));
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolVersion {
    V5 = 5,
}

impl Encodable for ProtocolVersion {
    fn rlp_append(&self, s: &mut RlpStream) {
        Encodable::rlp_append(&(*self as u8), s)
    }
}

impl Decodable for ProtocolVersion {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        let n: u8 = rlp.as_val()?;
        match n {
            5 => Ok(ProtocolVersion::V5),
            _ => Err(rlp::DecoderError::Custom("Invalid Protocol Version")),
        }
    }
}

#[derive(Debug, Clone, RlpDecodable, RlpEncodable, PartialEq, Eq)]
pub struct Capability {
    pub name: String,
    pub version: usize,
}

impl Capability {
    pub fn new(name: String, version: usize) -> Self {
        Self { name, version }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub protocol_version: ProtocolVersion,
    pub client_id: String,
    pub capabilities: Vec<Capability>,
    pub listen_port: u16,
    // secp256k1 public key
    pub peer_id: Vec<u8>,
}

impl Hello {
    pub const MESSAGE_ID: u8 = 0x00;
}

impl Encodable for Hello {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(5)
            .append(&self.protocol_version)
            .append(&self.client_id)
            .append_list(&self.capabilities)
            .append(&self.listen_port)
            .append(&self.peer_id);
    }
}

impl Decodable for Hello {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        crate::ensure(rlp.item_count()? == 5, rlp::DecoderError::RlpInvalidLength)?;
        let mut rlp = rlp.iter();
        Ok(Self {
            protocol_version: rlp.next().unwrap().as_val()?,
            client_id: rlp.next().unwrap().as_val()?,
            capabilities: rlp.next().unwrap().as_list()?,
            listen_port: rlp.next().unwrap().as_val()?,
            peer_id: rlp.next().unwrap().as_val()?,
        })
    }
}

#[derive(Debug, Clone, RlpDecodable, RlpEncodable)]
pub struct Ping {}

#[derive(Debug, Clone, RlpDecodable, RlpEncodable)]
pub struct Pong {}

#[derive(Debug, Clone, RlpDecodable, RlpEncodable)]
pub struct Disconnect {
    pub reason: u8,
}

#[derive(Debug, Clone)]
pub enum RlpxMessage {
    Hello(Hello),
    Ping(Ping),
    Pong(Pong),
    Disconnect(Disconnect),
}

impl RlpxMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        match self {
            RlpxMessage::Hello(hello) => {
                out.push(Hello::MESSAGE_ID);
                let encoded = rlp::encode(hello);
                out.extend(encoded)
            }
            _ => unimplemented!(),
        }
        out
    }

    pub fn decode(data: impl AsRef<[u8]>) -> Result<Self, RlpxError> {
        let (message_id, encoded) = data.as_ref().split_at(1);
        let message_id: u8 = rlp::decode(message_id)?;
        match message_id {
            Hello::MESSAGE_ID => Ok(Self::Hello(rlp::decode(&encoded)?)),
            _ => unimplemented!(),
        }
    }
}
