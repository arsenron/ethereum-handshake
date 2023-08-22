# Ethereum Node Network Handshake Implementation

This repository contains an implementation of a network handshake with an Ethereum node. The network handshake is a crucial part of establishing communication and synchronization between nodes in the Ethereum network. While the current implementation successfully accomplishes basic handshake functionality, there are certain features that can be added to enhance its capabilities.


## Background

RLPx protocol - is a TCP-based transport protocol used for communication among Ethereum nodes. The protocol carries encrypted messages belonging to one or more 'capabilities' which are negotiated during connection establishment. The current implementation is relied upon https://github.com/ethereum/devp2p/blob/master/rlpx.md.


## What is done

- **ECIES Encryption**.  Asymmetric encryption method used in the RLPx handshake. It is done inside `handshake.rs` module.
- **Framing**. Spltting a packet into the header and the body. It is done inside `rlpx.rs` module.
- **MAC**. Message authentication in RLPx. Verifies authentication of the remote peer by dynamically updating `MAC` state. It is done inside `mac.rs` module.
- **p2p Capability**. Now only two messages are implemented - `Hello`, which is the first packet sent over the established Ecies connection, and sent once by both sides. `Disconnect` - Inform the peer that a disconnection is imminent; if received, a peer should disconnect immediately. 


## What can be added/improved

- **Snappy compression**. All the messages after `Hello` message MUST be snappy-compressed.
- **TCP initial timeout**. Abort the program if TCP stream is not established for something like 15 secs.
- **More tests and tracing**. Add more tests to be more confident in the implementation. 



## How to run 

Very simple. Just provide one argument to the binary, that is `enode_id` (See https://ethereum.org/en/developers/docs/networking-layer/network-addresses/#enode). For example, you can try the following:

```sh
cargo run enode://143e11fb766781d22d92a2e33f8f104cddae4411a122295ed1fdb6638de96a6ce65f5b7c964ba3763bba27961738fef7d3ecc739268f3e5e771fb4c87b6234ba@146.190.1.103:30303
```

Here is one caveat. All the public nodes are protected meaning that there are some limits of how many connections per frame of time can be established. That means that if we try to establish handshake two times in a row, the second attempt will likely fail. But it will work after some time again.

To test against the local node, one simple solution would be to run a node inside a docker container. To have a `geth` node running, enter the following command:

```sh
docker run -p 8545:8545 -p 30303:30303 ethereum/client-go --syncmode light
```
In the logs, in the last few lines, you will see your `enode_id`. So just provide it to the app.
