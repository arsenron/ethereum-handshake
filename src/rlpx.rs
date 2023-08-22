use crate::handshake::HandshakeStream;
use crate::{ensure, handshake::SessionSecrets};
use crate::{id_to_public_key, mac, public_key_to_id};
use byteorder::{BigEndian, ByteOrder, ReadBytesExt};
use cipher::StreamCipher;
use futures::{SinkExt, TryStreamExt};
use rlp::{Decodable, Encodable, RlpDecodable, RlpEncodable, RlpStream};
use secp256k1::PublicKey;
use std::io;
use tokio::net::TcpStream;
use tokio_util::codec::{Decoder, Encoder};
use tracing::info;

pub const ETH_66: usize = 66;
pub const ETH_67: usize = 67;
pub const ETH_68: usize = 68;
/// 16 mb
const MAX_PAYLOAD_SIZE: usize = 16 * 1024 * 1024;
/// Header size + MAC size
const HEADER_SIZE: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum RlpxError {
    #[error("IO error")]
    IO(#[from] io::Error),
    #[error("Secp256k1 error - `{0:?}`")]
    Secp256k1(#[from] secp256k1::Error),
    #[error("Tag check failure")]
    TagDecryptFailed,
    #[error("Invalid RLP")]
    InvalidRlp(#[from] rlp::DecoderError),
    #[error("Stream has been closed")]
    StreamClosed,
    #[error("Invalid size")]
    FromInt(#[from] std::num::TryFromIntError),
    #[error("Unexpected message received")]
    UnexpectedMessage,
    #[error("Payload is too large to consume")]
    PayloadTooLarge,
    #[error("Incompatible protocols")]
    IncompatibleProtocols,
    #[error("No matched capabilities with the remote peer")]
    CapabilitiesMismatched,
}

/// Session keys and dynamically updatec MAC state
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
        self.ingress_mac.update_header(header);
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

/// State for framing. First we are getting a header, then we read a body.
#[derive(Debug, Clone, Copy)]
enum RlpxState {
    Header,
    /// Size of the encoded (rlp) body derived in `Header`
    Body(usize),
}

/// A stream implementing RLPx protocol.
///
/// See https://github.com/ethereum/devp2p/blob/master/rlpx.md
pub struct RlpxStream {
    io: tokio_util::codec::Framed<TcpStream, Rlpx>,
}

impl RlpxStream {
    pub fn new(handshake_stream: HandshakeStream, secrets: SessionSecrets) -> Self {
        // in case we also received a `Hello` message in previous stream, we
        // transfer the remaining bytes to a new rlpx stream.
        let buf_remaining = handshake_stream.read_buffer();
        let rlpx = Rlpx::new(secrets);
        let mut io = rlpx.framed(handshake_stream.into_inner());
        io.read_buffer_mut().extend_from_slice(&buf_remaining);
        Self { io }
    }

    pub async fn handshake(&mut self, hello_msg: Hello) -> Result<(), RlpxError> {
        info!("Sending hello message to the remote - {hello_msg:?}");

        let encoded = RlpxMessage::Hello(hello_msg.clone()).encode();
        self.io.send(encoded).await?;

        let msg = self.io.try_next().await?.ok_or(RlpxError::StreamClosed)?;
        let rlpx_message = RlpxMessage::decode(msg)?;
        // We expect the first message to be hello or disconnect
        let remote_hello_msg = match rlpx_message {
            RlpxMessage::Hello(hello) => hello,
            RlpxMessage::Disconnect(disconnect) => {
                tracing::error!("Received disconnect message. Reason {disconnect:?}");
                return Err(RlpxError::StreamClosed);
            }
            _ => {
                tracing::error!("Received unexpected message. Expected Hello or Disconnect");
                return Err(RlpxError::UnexpectedMessage);
            }
        };
        info!("Received hello message from the remote: {remote_hello_msg:?}");
        info!("Verifying capabilities");

        ensure(
            hello_msg.protocol_version == remote_hello_msg.protocol_version,
            RlpxError::IncompatibleProtocols,
        )?;
        let shared_capabilities =
            find_shared_capabilities(hello_msg.capabilities, remote_hello_msg.capabilities);
        ensure(
            !shared_capabilities.is_empty(),
            RlpxError::CapabilitiesMismatched,
        )?;

        info!("Shared capabilities with the remote peer - {shared_capabilities:?}");

        Ok(())
    }

    pub async fn disconnect(&mut self) -> Result<(), RlpxError> {
        // todo: this MUST be snappy compressed, now it does not work
        let disconnect = RlpxMessage::Disconnect(Disconnect { reason: 0x08 }).encode();
        self.io.send(disconnect).await?;

        Ok(())
    }
}

fn find_shared_capabilities(local: Vec<Capability>, remote: Vec<Capability>) -> Vec<Capability> {
    local
        .iter()
        .filter(|lc| remote.iter().any(|rc| &rc == lc))
        .cloned()
        .collect()
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
                    if body_size >= MAX_PAYLOAD_SIZE {
                        return Err(RlpxError::PayloadTooLarge);
                    }
                    self.state = RlpxState::Body(body_size);
                }
                RlpxState::Body(body_size) => {
                    let expected_size = if body_size % 16 == 0 {
                        body_size
                    } else {
                        // align data to 16 bytes + 16 byte for mac
                        (body_size | 31) + 1
                    };
                    if src.len() < expected_size {
                        return Ok(None);
                    }
                    let body_encrypted = src.split_to(expected_size).to_vec();
                    let mut body = self.read_body(body_encrypted)?;
                    // Pop padded data
                    if body_size != expected_size {
                        for _ in 0..expected_size - body_size - 16 {
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
    pub fn new(name: impl AsRef<str>, version: usize) -> Self {
        Self {
            name: name.as_ref().to_owned(),
            version,
        }
    }
}

/// The first "high-level" message to be exchanged between peers
/// after establishing a "Ecies" connection.
///
/// See https://github.com/ethereum/devp2p/blob/master/rlpx.md#hello-0x00
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub protocol_version: ProtocolVersion,
    pub client_id: String,
    pub capabilities: Vec<Capability>,
    pub listen_port: u16,
    // secp256k1 public key
    pub peer_id: PublicKey,
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
            .append(&public_key_to_id(&self.peer_id).as_slice());
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
            peer_id: id_to_public_key(
                rlp.next()
                    .unwrap()
                    .as_val::<Vec<u8>>()?
                    .try_into()
                    .map_err(|_| rlp::DecoderError::RlpInvalidLength)?,
            )
            .map_err(|_| rlp::DecoderError::Custom("Invalid peer id received"))?,
        })
    }
}

#[derive(Debug, Clone, RlpDecodable, RlpEncodable)]
pub struct Ping {}

#[derive(Debug, Clone, RlpDecodable, RlpEncodable)]
pub struct Pong {}

// todo(type safety): make `reason` as Enum instead of u8
#[derive(Clone, RlpEncodable)]
pub struct Disconnect {
    pub reason: u8,
}

impl std::fmt::Debug for Disconnect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.reason {
            0x00 => {
                write!(f, "0x00 - Disconnect requested")
            }
            0x01 => {
                write!(f, "0x01 - TCP sub-system error")
            }
            0x02 => {
                write!(f, "0x02 - Breach of protocol,")
            }
            0x03 => {
                write!(f, "0x03 - Useless peer")
            }
            0x04 => {
                write!(f, "0x04 - Too many peers")
            }
            0x05 => {
                write!(f, "0x05 - Already connected")
            }
            0x06 => {
                write!(f, "0x06 - Incompatible P2P protocol version")
            }
            0x07 => {
                write!(f, "0x07 - Null node identity received")
            }
            0x08 => {
                write!(f, "0x08 - Client quitting")
            }
            0x09 => {
                write!(f, "0x09 - Unexpected identity in handshake")
            }
            0x0a => {
                write!(f, "0x0a - Identity is the same as this node")
            }
            0x0b => {
                write!(f, "0x0b - Ping timeout")
            }
            0x10 => {
                write!(f, "0x10 - Some other reason")
            }
            _ => {
                write!(f, "Unknown reason")
            }
        }
    }
}

impl Decodable for Disconnect {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        Ok(Self {
            reason: rlp.as_val()?,
        })
    }
}

impl Disconnect {
    pub const MESSAGE_ID: u8 = 0x01;
}

/// Rlpx messages.
///
/// https://github.com/ethereum/devp2p/blob/master/rlpx.md#p2p-capability
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
                out.extend(rlp::encode(&Hello::MESSAGE_ID));
                out.extend(rlp::encode(hello))
            }
            RlpxMessage::Disconnect(disconnect) => {
                out.extend(rlp::encode(&Disconnect::MESSAGE_ID));
                out.extend(rlp::encode(disconnect))
            }
            _ => unimplemented!(),
        }
        out
    }

    pub fn decode(data: impl AsRef<[u8]>) -> Result<Self, RlpxError> {
        let (message_id, encoded) = data.as_ref().split_at(1);
        let message_id: u8 = rlp::decode(message_id)?;
        match message_id {
            Hello::MESSAGE_ID => Ok(Self::Hello(rlp::decode(encoded)?)),
            Disconnect::MESSAGE_ID => Ok(Self::Disconnect(rlp::decode(encoded)?)),
            _ => unimplemented!("{message_id:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{SecretKey, SECP256K1};

    #[test]
    fn test_shared_capabilities() {
        let local = vec![Capability::new("any", 66), Capability::new("any", 67)];

        let remote = vec![Capability::new("any", 60), Capability::new("anyy", 66)];
        assert!(find_shared_capabilities(local.clone(), remote).is_empty());

        let remote = vec![Capability::new("any", 66), Capability::new("any", 67)];
        assert_eq!(find_shared_capabilities(local.clone(), remote).len(), 2);

        let remote = vec![];
        assert!(find_shared_capabilities(local.clone(), remote).is_empty());
    }

    #[test]
    fn test_rlp_hello() {
        let secret_key = SecretKey::new(&mut rand::thread_rng());
        let public_key = secret_key.public_key(SECP256K1);
        let mut hello = Hello {
            protocol_version: ProtocolVersion::V5,
            client_id: "ethereum-killer/0.1.0".to_string(),
            capabilities: vec![Capability::new("eth", ETH_67)],
            listen_port: 30303,
            peer_id: public_key,
        };

        let encoded = rlp::encode(&mut hello).to_vec();
        let decoded: Hello = rlp::decode(&encoded).unwrap();

        assert_eq!(decoded, hello)
    }
}
