use rlp::{Encodable, RlpStream};

type Hash = [u8; 32];

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
    Frontier = 1,
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
    td: num_bigint::BigInt,
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

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::{BigInt, Sign};

    fn to_hash(s: &str) -> Hash {
        hex::decode(s).unwrap().try_into().unwrap()
    }

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

fn main() {
    println!("Hello, world!");
}
