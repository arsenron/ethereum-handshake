pub mod handshake;
pub mod mac;
pub mod rlpx;

use std::net::SocketAddr;

use handshake::HandshakeStream;
use regex::Regex;
use rlp::RlpIterator;
use rlpx::{Capability, Hello, ProtocolVersion, RlpxStream, ETH_68};
use secp256k1::{rand, PublicKey, SecretKey, SECP256K1};
use tracing::info;

fn parse_args() -> EnodeId {
    let Some(enode_id) = std::env::args().nth(1) else {
        eprintln!(
            "Please provide a `enode_id` of the remote \
            host to run a handshake. For example with Cargo - `cargo run <enode_id>`"
        );
        std::process::exit(101);
    };
    let Ok(enode_id) = EnodeId::try_from(enode_id.as_str()) else {
        eprintln!(
            "Could not parse provided `enode id`. It should look like: \
            `enode://9e9492e2e8836114cc75f5b929784f4f46c324ad01daf87d956f98b3b6c5fcba95524d6e5cf9861dc96a2c8a171ea7105bb554a197455058de185fa870970c7c@138.68.123.152:30303` "
        );
        std::process::exit(101);
    };

    enode_id
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    info!("Starting the application");

    if let Err(e) = run().await {
        tracing::error!("Could not perform a handshake with a remote node. Error received - {e:?}")
    }

    info!("Bye!");

    Ok(())
}

/// Actually performs a handshake process to a remote peer
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let enode_id = parse_args();

    let private_key = SecretKey::new(&mut rand::thread_rng());
    let public_key = PublicKey::from_secret_key(SECP256K1, &private_key);

    let mut handshake_stream = HandshakeStream::new(enode_id, private_key).await;
    let session_secrets = handshake_stream.establish_session_keys().await?;

    let mut rlpx_stream = RlpxStream::new(handshake_stream, session_secrets);

    let hello_message = Hello {
        protocol_version: ProtocolVersion::V5,
        client_id: "Beth/v1.2.0-super-stable-e501bs2h/redox-arm64/rust1.79".into(),
        capabilities: vec![Capability::new("eth", ETH_68), Capability::new("les", 4)],
        listen_port: 0,
        peer_id: public_key,
    };

    rlpx_stream.handshake(hello_message).await?;
    info!("Handshake succeeded! Closing the connection...");
    rlpx_stream.disconnect().await?;

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
    key.serialize_uncompressed()[1..]
        .try_into()
        .expect("Unfallible")
}

fn rlp_next<const C: usize>(rlp: &mut RlpIterator) -> Result<[u8; C], rlp::DecoderError> {
    // cannot panic as we explicitly checked the length if the `rlp` iterator
    rlp.next()
        .unwrap()
        .as_val::<Vec<u8>>()?
        .try_into()
        .map_err(|_| rlp::DecoderError::RlpInvalidLength)
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
