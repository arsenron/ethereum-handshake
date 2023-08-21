pub mod handshake;
pub mod mac;
pub mod rlpx;

use std::net::SocketAddr;

use handshake::{Handshake, HandshakeStream};
use regex::Regex;
use rlp::RlpIterator;
use rlpx::{Capability, Hello, ProtocolVersion, RlpxStream, ETH_68};
use secp256k1::{rand, PublicKey, SecretKey, SECP256K1};
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let enode_id = "enode://d620a51a1d62564e9a9a127812e59ec82f3cade01db0abc51797a2f68e4db81ffe54aecd9bb943664f9f702583248d6905a1cbf957689209bae8f24d7254f6c5@127.0.0.1:30303";
    let enode_id: EnodeId = enode_id.try_into().unwrap();

    tracing_subscriber::fmt::init();
    info!("Starting the application");

    let private_key = SecretKey::new(&mut rand::thread_rng());
    let public_key = PublicKey::from_secret_key(SECP256K1, &private_key);
    let handshake = Handshake::new(private_key, Some(enode_id.peer_id));

    let mut handshake_stream = HandshakeStream::new(enode_id.socket_addr, handshake).await;
    let session_secrets = handshake_stream.establish_session_keys().await?;
    let mut rlpx_stream = RlpxStream::new(handshake_stream.into_inner(), session_secrets);

    let hello_message = Hello {
        protocol_version: ProtocolVersion::V5,
        client_id: "Ethereum(++)/1.0.0".into(),
        capabilities: vec![Capability::new("eth".into(), ETH_68)],
        listen_port: 0,
        peer_id: public_key_to_id(&public_key).to_vec(),
    };

    rlpx_stream.handshake(hello_message).await?;

    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    Ok(())
}

pub fn ensure<E>(condition: bool, error: E) -> Result<(), E> {
    if condition {
        Ok(())
    } else {
        Err(error)
    }
}

pub fn xor<const C: usize>(arr1: [u8; C], arr2: [u8; C]) -> [u8; C] {
    let mut arr = [0; C];
    for i in 0..C {
        arr[i] = arr1[i] ^ arr2[i]
    }
    arr
}

pub fn id_to_public_key(id: [u8; 64]) -> Result<PublicKey, secp256k1::Error> {
    let mut s = [0u8; 65];
    // SECP256K1_TAG_PUBKEY_UNCOMPRESSED = 0x04
    s[0] = 4;
    s[1..].copy_from_slice(&id[..]);
    PublicKey::from_slice(&s)
}

pub fn public_key_to_id(key: &PublicKey) -> [u8; 64] {
    key.serialize_uncompressed()[1..].try_into().unwrap()
}

fn rlp_next<const C: usize>(rlp: &mut RlpIterator) -> Result<[u8; C], rlp::DecoderError> {
    // cannot panic as we explicitly checked the length if the `rlp` iterator
    Ok(rlp
        .next()
        .unwrap()
        .as_val::<Vec<u8>>()?
        .try_into()
        .map_err(|_| rlp::DecoderError::RlpInvalidLength)?)
}

#[derive(Debug, Clone)]
pub struct EnodeId {
    pub peer_id: [u8; 64],
    pub socket_addr: SocketAddr,
}

impl<'a> TryFrom<&'a str> for EnodeId {
    type Error = &'a str;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let re = Regex::new(r"^enode://([0-9a-fA-F]{128})@(.*)").expect("Unfallible");
        let captures = re.captures(value).ok_or(value)?;

        let peer_id = captures.get(1).ok_or(value)?;
        let peer_id = hex::decode(peer_id.as_str().as_bytes()).map_err(|_| value)?;

        let socket_addr = captures.get(2).ok_or(value)?;
        let socket_addr: SocketAddr = socket_addr.as_str().parse().map_err(|_| value)?;

        Ok(EnodeId {
            // cannot panic as we checked in regex that the length is 64 byte
            peer_id: peer_id.try_into().unwrap(),
            socket_addr,
        })
    }
}

#[cfg(test)]
pub mod test_utils {
    pub fn to_hash(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rlpx::ETH_67;

    #[test]
    fn test_rlp_hello() {
        let secret_key = SecretKey::new(&mut rand::thread_rng());
        let peer_id = public_key_to_id(&secret_key.public_key(SECP256K1));
        let mut hello = Hello {
            protocol_version: ProtocolVersion::V5,
            client_id: "ethereum-killer/0.1.0".to_string(),
            capabilities: vec![Capability::new("eth".into(), ETH_67)],
            listen_port: 30303,
            peer_id: peer_id.to_vec(),
        };

        let encoded = rlp::encode(&mut hello).to_vec();
        let decoded: Hello = rlp::decode(&encoded).unwrap();

        assert_eq!(decoded, hello)
    }
}
