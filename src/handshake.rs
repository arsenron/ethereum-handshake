use crate::mac::MacState;
use crate::IV;
use bytes::{BufMut, Bytes, BytesMut};
use cipher::KeyIvInit;
use cipher::StreamCipher;
use ctr::Ctr64BE;
use futures::{SinkExt, TryStreamExt};
use hmac::digest::Digest;
use hmac::{Hmac, Mac};
use rand::Rng;
use rlp::{Decodable, Encodable, RlpStream};
use secp256k1::{PublicKey, SecretKey, SECP256K1};
use sha2::Sha256;
use std::io;
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio_util::codec::{Decoder, Encoder, Framed};
use tracing::info;

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
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
}

struct AuthMessage {
    signature: [u8; 65],
    initiator_public_key: PublicKey,
    nonce: [u8; 32],
    version: u32,
}

impl AuthMessage {
    const VERSION: u32 = 4;
}

impl Encodable for AuthMessage {
    fn rlp_append(&self, s: &mut RlpStream) {
        let uncompressed = self.initiator_public_key.serialize_uncompressed();
        s.begin_list(4)
            .append(&self.signature.as_slice())
            .append(&&uncompressed[1..])
            .append(&self.nonce.as_slice())
            .append(&self.version);
    }
}

impl Decodable for AuthMessage {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        crate::ensure(rlp.is_list(), rlp::DecoderError::RlpExpectedToBeList)?;
        crate::ensure(rlp.item_count()? >= 4, rlp::DecoderError::RlpInvalidLength)?;
        let mut rlp = rlp.iter();
        let signature: [u8; 65] = crate::rlp_next(&mut rlp)?;
        let public_key: [u8; 64] = crate::rlp_next(&mut rlp)?;
        let public_key = crate::id_to_public_key(public_key)
            .map_err(|_| rlp::DecoderError::Custom("Invalid public key"))?;
        let nonce: [u8; 32] = crate::rlp_next(&mut rlp)?;
        Ok(Self {
            signature,
            initiator_public_key: public_key,
            nonce,
            version: rlp.next().unwrap().as_val()?,
        })
    }
}

/// The first message a server sends to a client
struct AuthAck {
    remote_ephemeral_public_key: PublicKey,
    nonce: [u8; 32],
}

impl Decodable for AuthAck {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        let mut rlp = rlp.iter();
        let public_key: [u8; 64] = crate::rlp_next(&mut rlp)?;
        let public_key = crate::id_to_public_key(public_key)
            .map_err(|_| rlp::DecoderError::Custom("Invalid public key"))?;
        let nonce: [u8; 32] = crate::rlp_next(&mut rlp)?;
        Ok(Self {
            remote_ephemeral_public_key: public_key,
            nonce,
        })
    }
}

pub struct Handshake {
    private_key: SecretKey,
    public_key: PublicKey,
    remote_public_key: Option<PublicKey>,
    local_nonce: [u8; 32],
    _ephemeral_public_key: PublicKey,
    ephemeral_private_key: SecretKey,

    // To be defined in the handshake process
    /// For initiator, this is `AuthMessage`
    local_init_msg: Option<Vec<u8>>,
    /// For initiator, this is `AuthAck`
    remote_init_msg: Option<Vec<u8>>,
    remote_nonce: Option<[u8; 32]>,
    ephemeral_shared_secret: Option<[u8; 32]>,
    #[cfg(test)]
    remote_ephemeral_public_key: Option<PublicKey>,
}

impl Handshake {
    pub fn new(private_key: SecretKey, remote_enode_id: Option<[u8; 64]>) -> Self {
        let public_key = PublicKey::from_secret_key(SECP256K1, &private_key);
        let remote_public_key = {
            if let Some(id) = remote_enode_id {
                Some(crate::id_to_public_key(id).unwrap())
            } else {
                None
            }
        };
        let ephemeral_secret_key = SecretKey::new(&mut rand::thread_rng());
        let ephemeral_public_key = PublicKey::from_secret_key(SECP256K1, &ephemeral_secret_key);
        Self {
            private_key,
            public_key,
            remote_public_key,
            local_nonce: rand::thread_rng().gen(),
            ephemeral_private_key: ephemeral_secret_key,
            _ephemeral_public_key: ephemeral_public_key,

            remote_init_msg: None,
            local_init_msg: None,
            remote_nonce: None,
            ephemeral_shared_secret: None,
            #[cfg(test)]
            remote_ephemeral_public_key: None,
        }
    }

    /// Returns `R || iv || c || d` as described in
    /// https://github.com/ethereum/devp2p/blob/master/rlpx.md#ecies-encryption
    fn encrypt_message(&self, data: Vec<u8>) -> BytesMut {
        // R + iv + c + d
        let total_size: u16 = 65 + 16 + data.len() as u16 + 32;
        let mut encrypted = BytesMut::with_capacity(total_size as usize);

        let r = SecretKey::new(&mut rand::thread_rng());
        let R = PublicKey::from_secret_key(SECP256K1, &r).serialize_uncompressed();
        let iv: IV = rand::thread_rng().gen();
        let x = create_shared_secret_x(&self.remote_public_key.unwrap(), &r);

        let mut key = [0u8; 32];
        concat_kdf::derive_key_into::<Sha256>(x.as_slice(), &[], &mut key).unwrap();

        let (Ke, Km) = key.split_at(32 / 2);
        let mut cipher = Ctr64BE::<aes::Aes128>::new(Ke.into(), iv.as_ref().into());
        let mut c = data;
        cipher.apply_keystream(&mut c);

        let d = hmac_256(
            Km,
            &[
                iv.as_slice(),
                c.as_slice(),
                total_size.to_be_bytes().as_slice(),
            ],
        );

        encrypted.put_slice(R.as_slice());
        encrypted.put_slice(iv.as_slice());
        encrypted.put_slice(&c[..]);
        encrypted.put_slice(&d[..]);

        encrypted
    }

    fn create_auth_message(&self) -> AuthMessage {
        let mut x = create_shared_secret_x(&self.remote_public_key.unwrap(), &self.private_key);
        // xor in-place
        for (b1, b2) in x.iter_mut().zip(self.local_nonce.iter()) {
            *b1 ^= *b2;
        }
        let signed = x;
        let (recovery_id, sig) = SECP256K1
            .sign_ecdsa_recoverable(
                &secp256k1::Message::from_slice(signed.as_slice()).unwrap(),
                &self.ephemeral_private_key,
            )
            .serialize_compact();

        let mut signature = [0u8; 65];
        signature[..64].copy_from_slice(&sig);
        signature[64] = recovery_id.to_i32() as u8;

        AuthMessage {
            signature,
            initiator_public_key: self.public_key,
            nonce: self.local_nonce,
            version: AuthMessage::VERSION,
        }
    }

    fn decrypt_message(&self, data: Vec<u8>) -> Result<Vec<u8>, HandshakeError> {
        let mut data = Bytes::from(data);
        let total_size_bytes = data.split_to(2);
        let total_size = u16::from_be_bytes([total_size_bytes[0], total_size_bytes[1]]);
        debug_assert!(data.len() >= total_size as usize);
        let public_key = PublicKey::from_slice(&data.split_to(65))?;

        let iv = data.split_to(16);
        let (encrypted_data, tag) = data.split_at(data.len() - 32);

        let x = create_shared_secret_x(&public_key, &self.private_key);
        let mut key = [0u8; 32];
        concat_kdf::derive_key_into::<Sha256>(x.as_slice(), &[], &mut key).unwrap();

        let (Ke, Km) = key.split_at(32 / 2);

        let check_tag = hmac_256(Km, &[&iv[..], encrypted_data, total_size_bytes.as_ref()]);
        if check_tag != tag {
            return Err(HandshakeError::TagDecryptFailed);
        }

        let mut decrypted_data = encrypted_data.to_vec();
        let mut decryptor = Ctr64BE::<aes::Aes128>::new(Ke.into(), iv.as_ref().into());
        decryptor.apply_keystream(&mut decrypted_data);

        Ok(decrypted_data)
    }

    fn read_ack(&mut self, data: Vec<u8>) -> Result<AuthAck, HandshakeError> {
        self.remote_init_msg = Some(data.clone());
        let decrypted = self.decrypt_message(data)?;
        let auth_message: AuthAck = rlp::decode(&decrypted)?;
        Ok(auth_message)
    }

    /// Setups aes and MAC
    fn setup_session_state(&mut self) -> SessionSecrets {
        let mut hasher = sha3::Keccak256::new();
        hasher.update(self.remote_nonce.unwrap());
        hasher.update(self.local_nonce);
        let h_nonce: [u8; 32] = hasher.finalize().into(); // keccak256(nonce || initiator-nonce)
        let iv: IV = [0; 16];
        let shared_secret: [u8; 32] = {
            let mut hasher = sha3::Keccak256::new();
            hasher.update(self.ephemeral_shared_secret.as_ref().unwrap());
            hasher.update(h_nonce.as_ref());
            hasher.finalize().into()
        };

        let aes_secret: [u8; 32] = {
            let mut hasher = sha3::Keccak256::new();
            hasher.update(self.ephemeral_shared_secret.as_ref().unwrap());
            hasher.update(shared_secret.as_ref());
            hasher.finalize().into()
        };

        let ingress_aes =
            Ctr64BE::<aes::Aes256>::new(aes_secret.as_ref().into(), iv.as_ref().into());
        let egress_aes =
            Ctr64BE::<aes::Aes256>::new(aes_secret.as_ref().into(), iv.as_ref().into());

        let mac_secret: [u8; 32] = {
            let mut hasher = sha3::Keccak256::new();
            hasher.update(self.ephemeral_shared_secret.as_ref().unwrap());
            hasher.update(aes_secret.as_ref());
            hasher.finalize().into()
        };

        let mut ingress_mac = MacState::new(mac_secret);
        ingress_mac.update(crate::xor(mac_secret, self.local_nonce).as_ref());
        ingress_mac.update(self.remote_init_msg.as_deref().unwrap());

        let mut egress_mac = MacState::new(mac_secret);
        egress_mac.update(crate::xor(mac_secret, self.remote_nonce.unwrap()).as_ref());
        egress_mac.update(self.local_init_msg.as_deref().unwrap());

        SessionSecrets {
            ingress_aes,
            egress_aes,
            ingress_mac,
            egress_mac,
        }
    }
}

pub struct SessionSecrets {
    pub ingress_aes: Ctr64BE<aes::Aes256>,
    pub egress_aes: Ctr64BE<aes::Aes256>,
    pub ingress_mac: MacState,
    pub egress_mac: MacState,
}

fn hmac_256(Km: &[u8], data: &[&[u8]]) -> [u8; 32] {
    let mac = Sha256::digest(Km);
    let mut hmac = Hmac::<Sha256>::new_from_slice(mac.as_slice()).unwrap();
    for d in data {
        hmac.update(d)
    }
    hmac.finalize().into_bytes().into()
}

// Computes shared secret and returns only x coordinate
fn create_shared_secret_x(remote_public_key: &PublicKey, private_key: &SecretKey) -> [u8; 32] {
    let point = secp256k1::ecdh::shared_secret_point(remote_public_key, private_key);
    point[0..32].try_into().unwrap()
}

impl Encoder<()> for Handshake {
    type Error = io::Error;

    fn encode(&mut self, _item: (), dst: &mut BytesMut) -> Result<(), Self::Error> {
        let auth_message = self.create_auth_message();
        let mut encoded_auth_message = rlp::encode(&auth_message);
        // Pad with random amount of data to make
        // the message distinguishable from pre-EIP-8 handshakes.
        encoded_auth_message.resize(rand::thread_rng().gen_range(200..=300), 0);
        let encrypted = self.encrypt_message(encoded_auth_message.into());
        let total_size = encrypted.len() as u16;
        self.local_init_msg = Some(encrypted.to_vec());
        dst.extend_from_slice(total_size.to_be_bytes().as_slice());
        dst.extend_from_slice(encrypted.as_ref());

        Ok(())
    }
}

impl Decoder for Handshake {
    type Item = SessionSecrets;
    type Error = HandshakeError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 2 {
            return Ok(None);
        }
        let payload_size = u16::from_be_bytes([src[0], src[1]]) as usize;
        if payload_size > src.len() {
            return Ok(None);
        }
        let auth_ack = self.read_ack(src.to_vec())?;
        self.remote_nonce = Some(auth_ack.nonce);
        self.ephemeral_shared_secret = Some(create_shared_secret_x(
            &auth_ack.remote_ephemeral_public_key,
            &self.ephemeral_private_key,
        ));
        Ok(Some(self.setup_session_state()))
    }
}

pub struct HandshakeStream {
    io: Framed<TcpStream, Handshake>,
}

impl HandshakeStream {
    pub async fn new<A: ToSocketAddrs>(addr: A, handshake: Handshake) -> Self {
        let stream = TcpStream::connect(addr)
            .await
            .expect("Could not connect to a remote node");
        info!("Established tcp connection to the remote node");

        Self {
            io: handshake.framed(stream),
        }
    }

    pub async fn establish_session_keys(&mut self) -> Result<SessionSecrets, HandshakeError> {
        info!("Starting Ecies handshake");
        info!("Sending AuthMsg message");
        self.io.send(()).await?;
        let session_secrets = self
            .io
            .try_next()
            .await?
            .ok_or(HandshakeError::StreamClosed)?;
        info!("Ack received");
        Ok(session_secrets)
    }
}

#[cfg(test)]
#[allow(unused_imports)]
mod tests {
    use super::*;
    use crate::test_utils::*;
    use crate::{id_to_public_key, public_key_to_id, xor};
    use hex_literal::hex;
    use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};

    impl Handshake {
        /// eip-8 test data
        pub fn test_client() -> Self {
            let private_key = SecretKey::from_slice(&hex!(
                "49a7b37aa6f6645917e7b807e9d1c00d4fa71f18343b0d4122a4d2df64dd6fee"
            ))
            .unwrap();

            let ephemeral_secret_key = SecretKey::from_slice(&hex!(
                "869d6ecf5211f1cc60418a13b9d870b22959d0c16f02bec714c960dd2298a32d"
            ))
            .unwrap();

            let init_nonce =
                hex!("7e968bba13b6c50e2c4cd7f241cc0d64d1ac25c7f5952df231ac6a2bda8ee5d6");

            let server_secret_key = SecretKey::from_slice(&hex!(
                "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291"
            ))
            .unwrap();
            let server_public_key = PublicKey::from_secret_key(SECP256K1, &server_secret_key);

            let mut this = Self::new(private_key, Some(public_key_to_id(&server_public_key)));
            this.local_nonce = init_nonce;
            this.ephemeral_private_key = ephemeral_secret_key;
            this
        }

        pub fn test_server() -> Self {
            let ephemeral_secret_key = SecretKey::from_slice(&hex!(
                "e238eb8e04fee6511ab04c6dd3c89ce097b11f25d584863ac2b6d5b35b1847e4"
            ))
            .unwrap();

            let init_nonce =
                hex!("559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd");
            let private_key = SecretKey::from_slice(&hex!(
                "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291"
            ))
            .unwrap();
            let mut this = Self::new(private_key, None);
            this.local_nonce = init_nonce;
            this.ephemeral_private_key = ephemeral_secret_key;
            let ephemeral_public_key = PublicKey::from_secret_key(SECP256K1, &ephemeral_secret_key);
            this._ephemeral_public_key = ephemeral_public_key;
            this
        }

        fn validate_auth(&mut self, data: Vec<u8>) -> Result<(), HandshakeError> {
            let decrypted = self.decrypt_message(data)?;
            let auth_msg: AuthMessage = rlp::decode(&decrypted)?;
            let signature = RecoverableSignature::from_compact(
                &auth_msg.signature[..64],
                RecoveryId::from_i32(auth_msg.signature[64] as i32)?,
            )?;
            self.remote_public_key = Some(auth_msg.initiator_public_key);

            let x = create_shared_secret_x(&self.remote_public_key.unwrap(), &self.private_key);
            self.remote_nonce = Some(auth_msg.nonce);
            self.remote_ephemeral_public_key = Some(SECP256K1.recover_ecdsa(
                &secp256k1::Message::from_slice(xor(x, auth_msg.nonce).as_ref()).unwrap(),
                &signature,
            )?);
            self.ephemeral_shared_secret = Some(create_shared_secret_x(
                &self.remote_ephemeral_public_key.unwrap(),
                &self.ephemeral_private_key,
            ));

            Ok(())
        }
    }

    #[test]
    fn test_shared_secret() {
        let priv_key = SecretKey::from_slice(&hex!(
            "202a36e24c3eb39513335ec99a7619bad0e7dc68d69401b016253c7d26dc92f8"
        ))
        .unwrap();
        let remote_public_key = id_to_public_key(hex!("d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa4101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666")).unwrap();

        assert_eq!(
            create_shared_secret_x(&remote_public_key, &priv_key),
            hex!("821ce7e01ea11b111a52b2dafae8a3031a372d83bdf1a78109fa0783c2b9d5d3")
        )
    }

    // https://eips.ethereum.org/EIPS/eip-8 test data (see `RLPx Handshake` section)
    #[test]
    fn test_ecies() {
        // EIP-8 format with version 4 and no additional list elements
        let auth2 = hex!(
            "
                01b304ab7578555167be8154d5cc456f567d5ba302662433674222360f08d5f1534499d3678b513b
                0fca474f3a514b18e75683032eb63fccb16c156dc6eb2c0b1593f0d84ac74f6e475f1b8d56116b84
                9634a8c458705bf83a626ea0384d4d7341aae591fae42ce6bd5c850bfe0b999a694a49bbbaf3ef6c
                da61110601d3b4c02ab6c30437257a6e0117792631a4b47c1d52fc0f8f89caadeb7d02770bf999cc
                147d2df3b62e1ffb2c9d8c125a3984865356266bca11ce7d3a688663a51d82defaa8aad69da39ab6
                d5470e81ec5f2a7a47fb865ff7cca21516f9299a07b1bc63ba56c7a1a892112841ca44b6e0034dee
                70c9adabc15d76a54f443593fafdc3b27af8059703f88928e199cb122362a4b35f62386da7caad09
                c001edaeb5f8a06d2b26fb6cb93c52a9fca51853b68193916982358fe1e5369e249875bb8d0d0ec3
                6f917bc5e1eafd5896d46bd61ff23f1a863a8a8dcd54c7b109b771c8e61ec9c8908c733c0263440e
                2aa067241aaa433f0bb053c7b31a838504b148f570c0ad62837129e547678c5190341e4f1693956c
                3bf7678318e2d5b5340c9e488eefea198576344afbdf66db5f51204a6961a63ce072c8926c
            "
        );

        // EIP-8 format with version 56 and 3 additional list elements (sent from A to B)
        let auth3 = hex!(
            "
                01b8044c6c312173685d1edd268aa95e1d495474c6959bcdd10067ba4c9013df9e40ff45f5bfd6f7
                2471f93a91b493f8e00abc4b80f682973de715d77ba3a005a242eb859f9a211d93a347fa64b597bf
                280a6b88e26299cf263b01b8dfdb712278464fd1c25840b995e84d367d743f66c0e54a586725b7bb
                f12acca27170ae3283c1073adda4b6d79f27656993aefccf16e0d0409fe07db2dc398a1b7e8ee93b
                cd181485fd332f381d6a050fba4c7641a5112ac1b0b61168d20f01b479e19adf7fdbfa0905f63352
                bfc7e23cf3357657455119d879c78d3cf8c8c06375f3f7d4861aa02a122467e069acaf513025ff19
                6641f6d2810ce493f51bee9c966b15c5043505350392b57645385a18c78f14669cc4d960446c1757
                1b7c5d725021babbcd786957f3d17089c084907bda22c2b2675b4378b114c601d858802a55345a15
                116bc61da4193996187ed70d16730e9ae6b3bb8787ebcaea1871d850997ddc08b4f4ea668fbf3740
                7ac044b55be0908ecb94d4ed172ece66fd31bfdadf2b97a8bc690163ee11f5b575a4b44e36e2bfb2
                f0fce91676fd64c7773bac6a003f481fddd0bae0a1f31aa27504e2a533af4cef3b623f4791b2cca6
                d490
            "
        );

        // EIP-8 format with version 4 and no additional list elements (sent from B to A)
        let ack2 = hex!(
            "
                01ea0451958701280a56482929d3b0757da8f7fbe5286784beead59d95089c217c9b917788989470
                b0e330cc6e4fb383c0340ed85fab836ec9fb8a49672712aeabbdfd1e837c1ff4cace34311cd7f4de
                05d59279e3524ab26ef753a0095637ac88f2b499b9914b5f64e143eae548a1066e14cd2f4bd7f814
                c4652f11b254f8a2d0191e2f5546fae6055694aed14d906df79ad3b407d94692694e259191cde171
                ad542fc588fa2b7333313d82a9f887332f1dfc36cea03f831cb9a23fea05b33deb999e85489e645f
                6aab1872475d488d7bd6c7c120caf28dbfc5d6833888155ed69d34dbdc39c1f299be1057810f34fb
                e754d021bfca14dc989753d61c413d261934e1a9c67ee060a25eefb54e81a4d14baff922180c395d
                3f998d70f46f6b58306f969627ae364497e73fc27f6d17ae45a413d322cb8814276be6ddd13b885b
                201b943213656cde498fa0e9ddc8e0b8f8a53824fbd82254f3e2c17e8eaea009c38b4aa0a3f306e8
                797db43c25d68e86f262e564086f59a2fc60511c42abfb3057c247a8a8fe4fb3ccbadde17514b7ac
                8000cdb6a912778426260c47f38919a91f25f4b5ffb455d6aaaf150f7e5529c100ce62d6d92826a7
                1778d809bdf60232ae21ce8a437eca8223f45ac37f6487452ce626f549b3b5fdee26afd2072e4bc7
                5833c2464c805246155289f4
            "
        );

        // EIP-8 format with version 57 and 3 additional list elements (sent from B to A)
        let ack3 = hex!(
            "
                01f004076e58aae772bb101ab1a8e64e01ee96e64857ce82b1113817c6cdd52c09d26f7b90981cd7
                ae835aeac72e1573b8a0225dd56d157a010846d888dac7464baf53f2ad4e3d584531fa203658fab0
                3a06c9fd5e35737e417bc28c1cbf5e5dfc666de7090f69c3b29754725f84f75382891c561040ea1d
                dc0d8f381ed1b9d0d4ad2a0ec021421d847820d6fa0ba66eaf58175f1b235e851c7e2124069fbc20
                2888ddb3ac4d56bcbd1b9b7eab59e78f2e2d400905050f4a92dec1c4bdf797b3fc9b2f8e84a482f3
                d800386186712dae00d5c386ec9387a5e9c9a1aca5a573ca91082c7d68421f388e79127a5177d4f8
                590237364fd348c9611fa39f78dcdceee3f390f07991b7b47e1daa3ebcb6ccc9607811cb17ce51f1
                c8c2c5098dbdd28fca547b3f58c01a424ac05f869f49c6a34672ea2cbbc558428aa1fe48bbfd6115
                8b1b735a65d99f21e70dbc020bfdface9f724a0d1fb5895db971cc81aa7608baa0920abb0a565c9c
                436e2fd13323428296c86385f2384e408a31e104670df0791d93e743a3a5194ee6b076fb6323ca59
                3011b7348c16cf58f66b9633906ba54a2ee803187344b394f75dd2e663a57b956cb830dd7a908d4f
                39a2336a61ef9fda549180d4ccde21514d117b6c6fd07a9102b5efe710a32af4eeacae2cb3b1dec0
                35b9593b48b9d3ca4c13d245d5f04169b0b1
            "
        );

        let mut server = Handshake::test_server();
        server.validate_auth(auth2.to_vec()).unwrap();
        server.validate_auth(auth3.to_vec()).unwrap();

        let mut client = Handshake::test_client();
        client.read_ack(ack2.to_vec()).unwrap();
        client.read_ack(ack3.to_vec()).unwrap();
    }
}
