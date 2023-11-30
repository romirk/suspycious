Protocol Spec
=============

## Message Framing

### Header

| Field           | Size (bytes) | Description        |
|-----------------|-------------:|--------------------|
| `connection_id` |            4 | Connection ID      |
| `packet_id`     |            8 | Packet ID          |
| `ack_id`        |            8 | Acknowledgement ID |
| `flags`         |            1 | Flags              |
| **Total**       |       **21** |                    |

### Payload

The payload is a variable length byte array. The maximum size of the payload
is set by network maximum transmission unit (MTU) size. The payload is
encrypted using the ChaCha20 stream cipher.

Clients sending large messages should split the message into multiple packets
and send them sequentially. The `packet_id` field is used to reassemble the
message on the receiving end. A packet may contain fragments of multiple
messages.

### Tag

The tag is a 16 byte message authentication code (MAC) generated using the
ChaCha20-Poly1305 AEAD construction. The tag is generated using the following
parameters:

* `key`: 32 byte shared secret key
* `packet_id`: 8 byte packet ID
* `nonce`: 8 byte nonce

### Frame

    +--------+-------------------------+----------------+
    | Header | Payload (variable size) | Tag (16 bytes) |
    +--------+-------------------------+----------------+
