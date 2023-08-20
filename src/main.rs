#![allow(non_snake_case)]

mod handshake;

use bytes::BufMut;
use cipher::{BlockEncrypt, KeyIvInit, StreamCipher};
use futures::{SinkExt, TryStreamExt};
use handshake::{Handshake, HandshakeError, HandshakeStream};
use hmac::Mac;
use num_bigint::BigInt;
use rand::Rng;
use rlp::{Decodable, Encodable, RlpIterator, RlpStream};
use secp256k1::{rand, PublicKey, SecretKey};
use sha2::Digest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::ToSocketAddrs;
use tokio_util::codec::{Decoder, Encoder};
use tracing::info;

pub type Hash = [u8; 32];
pub type IV = [u8; 16];

/// Ethereum Foundation Go Bootnodes
pub static MAINNET_BOOTNODES : [&str; 4] = [
    "enode://d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa4101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666@18.138.108.67:30303",
    "enode://22a8232c3abc76a16ae9d6c3b164f98775fe226f0917b0ca871128a74a8e9630b458460865bab457221f1d448dd9791d24c4e5d88786180ac185df813a68d4de@3.209.45.79:30303",
    "enode://2b252ab6a1d0f971d9722cb839a42cb81db019ba44c08754628ab4a823487071b5695317c8ccd085219c3a03af063495b2f1da8d18218da2d6a82981b45e6ffc@65.108.70.101:30303",
    "enode://4aeb4ab6c14b23e2c4cfdce879c04b0748a20d8e9b59e25ded2a08143e265c6c25936e74cbc8e641e3312ca288673d91f2f93f8e277de3cfa444ecdaaf982052@157.90.35.166:30303",
];

/// GOERLI bootnodes
pub static TESTNET_BOOTNODES : [&str; 7] = [
    "enode://011f758e6552d105183b1761c5e2dea0111bc20fd5f6422bc7f91e0fabbec9a6595caf6239b37feb773dddd3f87240d99d859431891e4a642cf2a0a9e6cbb98a@51.141.78.53:30303",
    "enode://176b9417f511d05b6b2cf3e34b756cf0a7096b3094572a8f6ef4cdcb9d1f9d00683bf0f83347eebdf3b81c3521c2332086d9592802230bf528eaf606a1d9677b@13.93.54.137:30303",
    "enode://46add44b9f13965f7b9875ac6b85f016f341012d84f975377573800a863526f4da19ae2c620ec73d11591fa9510e992ecc03ad0751f53cc02f7c7ed6d55c7291@94.237.54.114:30313",
    "enode://b5948a2d3e9d486c4d75bf32713221c2bd6cf86463302339299bd227dc2e276cd5a1c7ca4f43a0e9122fe9af884efed563bd2a1fd28661f3b5f5ad7bf1de5949@18.218.250.66:30303",
    "enode://a61215641fb8714a373c80edbfa0ea8878243193f57c96eeb44d0bc019ef295abd4e044fd619bfc4c59731a73fb79afe84e9ab6da0c743ceb479cbb6d263fa91@3.11.147.67:30303",
    "enode://d4f764a48ec2a8ecf883735776fdefe0a3949eb0ca476bd7bc8d0954a9defe8fea15ae5da7d40b5d2d59ce9524a99daedadf6da6283fca492cc80b53689fb3b3@46.4.99.122:32109",
    "enode://d2b720352e8216c9efc470091aa91ddafc53e222b32780f505c817ceef69e01d5b0b0797b69db254c586f493872352f5a022b4d8479a00fc92ec55f9ad46a27e@88.99.70.182:30303",
];

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

#[derive(Debug, Copy, Clone)]
struct ForkId {
    /// CRC32 checksum of the genesis block and passed fork block numbers
    hash: [u8; 4],
    /// Block number of the next upcoming fork, or 0 if no forks are known
    next: u64,
}

impl Encodable for ForkId {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2)
            .append(&self.hash.as_slice())
            .append(&self.next);
    }
}

#[repr(u64)]
#[derive(Debug, Copy, Clone)]
enum Network {
    /// Mainnet
    Frontier = 1,
    /// Testnet
    Goerli = 5,
}

impl Encodable for Network {
    fn rlp_append(&self, s: &mut RlpStream) {
        Encodable::rlp_append(&(*self as u64), s)
    }
}

/// https://github.com/ethereum/devp2p/blob/master/caps/eth.md#status-0x00
#[derive(Debug, Clone)]
struct Status {
    version: u32,
    network: Network,
    td: BigInt,
    head: Hash,
    genesis: Hash,
    fork_id: ForkId,
}

impl Encodable for Status {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(6)
            .append(&self.version)
            .append(&self.network)
            .append(&self.td.to_bytes_be().1)
            .append(&self.head.as_slice())
            .append(&self.genesis.as_slice())
            .append(&self.fork_id);
    }
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

/// Continuously updated MAC states.
///
/// https://github.com/ethereum/devp2p/blob/master/rlpx.md#mac
struct MacState {
    /// Mac secret - keccak256(ephemeral-key || aes-secret)
    secret: [u8; 32],
    state: sha3::Keccak256,
}

impl MacState {
    pub fn new(secret: [u8; 32]) -> Self {
        Self {
            secret,
            state: sha3::Keccak256::new(),
        }
    }

    /// Update the internal keccak256 hasher with the given data
    pub fn update(&mut self, data: &[u8]) {
        self.state.update(data)
    }

    pub fn update_header(&mut self, header_ciphertext: &[u8]) {
        use cipher::KeyInit;
        let mut encrypted = self.digest();
        let aes = aes::Aes256Enc::new_from_slice(self.secret.as_ref()).unwrap();
        aes.encrypt_padded::<block_padding::NoPadding>(&mut encrypted, 16)
            .unwrap();
        for i in 0..header_ciphertext.len() {
            encrypted[i] ^= header_ciphertext[i];
        }
        self.state.update(encrypted)
    }

    /// Accumulate the given message body into the MAC's internal state.
    pub fn update_frame(&mut self, frame_ciphertext: &[u8]) {
        use cipher::KeyInit;
        self.state.update(frame_ciphertext);
        let prev = self.digest();
        let aes = aes::Aes256Enc::new_from_slice(self.secret.as_ref()).unwrap();
        let mut encrypted = self.digest();
        aes.encrypt_padded::<block_padding::NoPadding>(&mut encrypted, 16)
            .unwrap();
        for i in 0..16 {
            encrypted[i] ^= prev[i];
        }
        self.state.update(encrypted);
    }

    /// Returns last 16 byte of current's state hash
    pub fn digest(&self) -> [u8; 16] {
        let hash: [u8; 32] = self.state.clone().finalize().into();
        hash[..16].try_into().unwrap()
    }
}

#[tokio::main]
async fn main() -> Result<(), HandshakeError> {
    tracing_subscriber::fmt::init();
    tracing::info!("Starting the application");

    let secret_key = SecretKey::new(&mut rand::thread_rng());
    // let ecies = Ecies::new(
    //     secret_key,
    //     Some(decode("b5948a2d3e9d486c4d75bf32713221c2bd6cf86463302339299bd227dc2e276cd5a1c7ca4f43a0e9122fe9af884efed563bd2a1fd28661f3b5f5ad7bf1de5949").unwrap().try_into().unwrap())
    // );
    let handshake = Handshake::new(
        secret_key,
        Some(hex::decode("d620a51a1d62564e9a9a127812e59ec82f3cade01db0abc51797a2f68e4db81ffe54aecd9bb943664f9f702583248d6905a1cbf957689209bae8f24d7254f6c5").unwrap().try_into().unwrap())
    );

    info!("Opening tcp connection to the remote node");
    let mut handshake_stream = HandshakeStream::new("127.0.0.1:30303", handshake).await;
    let _session_secrets = handshake_stream.establish_session_keys().await?;

    Ok(())
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

#[cfg(test)]
pub mod test_utils {
    use super::*;

    pub fn to_hash(s: &str) -> Hash {
        hex::decode(s).unwrap().try_into().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;
    use num_bigint::Sign;

    // Test data is taken from go-ethereum
    #[test]
    fn test_encoding() {
        let status = Status {
            version: 10,
            network: Network::Frontier,
            td: BigInt::from_bytes_be(Sign::Plus, 0x80000_u32.to_be_bytes().as_slice()),
            head: to_hash("1c960a3e0e68da2013c4aba3cb0dad7f944431e4f6a6bf13d1c05a7b5f382a11"),
            genesis: to_hash("b1d281bbda7f5fbb1cf864e801bfe33c37d195c1eb7989e73b6b2d58b6b7f2ee"),
            fork_id: ForkId {
                hash: [67, 84, 41, 0],
                next: 0,
            },
        };
        let e = rlp::encode(&status);

        assert_eq!(
            hex::encode(e.to_vec()),
            "f84f0a0183080000a01c960a3e0e68da2013c4aba3cb0dad7f944431e4f6a6bf13d1c05a7b5f382a11a0b1d281bbda7f5fbb1cf864e801bfe33c37d195c1eb7989e73b6b2d58b6b7f2eec6844354290080"
        );

        let status = Status {
            version: 100500,
            network: Network::Goerli,
            td: BigInt::from_bytes_be(Sign::Plus, 0xca0000_u32.to_be_bytes().as_slice()),
            head: to_hash("abab00e1eed264acd16f717879110630619a947e7eb7179a7998af9cbf2a258a"),
            genesis: to_hash("b1d281bbda7f5fbb1cf864e801bfe33c37d195c1eb7989e73b6b2d58b6b7f2ee"),
            fork_id: ForkId {
                hash: [67, 84, 41, 0],
                next: 0,
            },
        };
        let e = rlp::encode(&status);

        assert_eq!(
            hex::encode(e.to_vec()),
            "f852830188940583ca0000a0abab00e1eed264acd16f717879110630619a947e7eb7179a7998af9cbf2a258aa0b1d281bbda7f5fbb1cf864e801bfe33c37d195c1eb7989e73b6b2d58b6b7f2eec6844354290080"
        );
    }
}
