use sha3::Digest;

/// Continuously updated MAC states.
///
/// https://github.com/ethereum/devp2p/blob/master/rlpx.md#mac
pub struct MacState {
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

    /// header-mac-seed = aes(mac-secret, keccak256.digest(egress-mac)[:16]) ^ header-ciphertext
    ///
    /// Update with header-mac-seed
    pub fn update_header(&mut self, header_ciphertext: &[u8]) {
        use cipher::{BlockEncrypt, KeyInit};
        let mut encrypted = self.digest(); //
        let aes = aes::Aes256Enc::new_from_slice(self.secret.as_ref()).unwrap();
        aes.encrypt_padded::<block_padding::NoPadding>(&mut encrypted, 16)
            .unwrap();
        for i in 0..header_ciphertext.len() {
            encrypted[i] ^= header_ciphertext[i];
        }
        self.state.update(encrypted)
    }

    /// Accumulate the given message body into the MAC's internal state.
    ///
    /// frame-mac-seed = aes(mac-secret, keccak256.digest(egress-mac)[:16]) ^ keccak256.digest(egress-mac)[:16]
    pub fn update_body(&mut self, frame_ciphertext: &[u8]) {
        use cipher::{BlockEncrypt, KeyInit};
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

    /// Returns last 16 byte of current's state hash.
    ///
    /// In Ethereum docs: keccak256.digest(mac)[:16]
    pub fn digest(&self) -> [u8; 16] {
        let hash: [u8; 32] = self.state.clone().finalize().into();
        hash[..16].try_into().unwrap()
    }
}
