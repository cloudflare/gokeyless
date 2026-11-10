## Protocol
The Cloudflare Keyless SSL client communicates to the server via a binary
protocol over a mutually authenticated TLS 1.2 tunnel.  Messages are in binary
format and identified by a unique ID.

Messages consist of a fixed length header, and a variable length body.  The
body of the message consists of a sequence of items in TLV (tag, length,
value) messages.

All messages with major version 1 will conform to the following
format.  The minor version is currently set to 0 and is reserved for
communicating policy information.

Header:

    0 - - 1 - - 2 - - 3 - - 4 - - 5 - - 6 - - 7 - - 8
    | Maj | Min |   Length  |          ID           |
    |                      Body                     |
    |                      Body                     | <- 8 + Length

Item:

    0 - - 1 - - 2 - - 3 - - 4 - - 5 - - 6 - - 7 - - 8
    | Tag |   Length  |          Data               |
    |                      Data                     | <- 3 + Length

All numbers are in network byte order (big endian).

The following tag values are possible for items:

    0x01 - Certificate Digest,
    0x02 - Server Name Indication,
    0x03 - Client's IP address,
    0x04 - Subject Key Identifier for the requested key,
    0x05 - Server's IP address,
    0x06 - Certificate ID,
    0x11 - Opcode,
    0x12 - Payload,
    0x13 - CustomFuncName, (for use with opcode 0x24)
    0x14 - Supplemental payload, whose meaning is not specified and must be predetermined between the server and client,
    0x15 - Binary encoded Jaeger span (https://www.jaegertracing.io/docs/1.19/client-libraries/#value)
    0x16 - ReqContext, request metadata,
    0x17 - ComplianceRegion,
    0x18 - Certificate usage, key selection metadata,

A requests contains a header and the following items:

    0x01 - length: 32 bytes, data: SHA256 of RSA modulus
    0x02 - length: variable, data: SNI string
    0x03 - length: 4 or 16 bytes, data: IPv4/6 address
    0x11 - length: 1, data: opcode describing operation
    0x12 - length: variable, data: payload to sign or encrypt

The following opcodes are supported in the opcode item:

    0x01 - operation: RSA decrypt payload 
    0x02 - operation: RSA sign MD5SHA1
    0x03 - operation: RSA sign SHA1
    0x04 - operation: RSA sign SHA224
    0x05 - operation: RSA sign SHA256
    0x06 - operation: RSA sign SHA384
    0x07 - operation: RSA sign SHA512
    0x12 - operation: ECDSA sign MD5SHA1
    0x13 - operation: ECDSA sign SHA1
    0x14 - operation: ECDSA sign SHA224
    0x15 - operation: ECDSA sign SHA256
    0x16 - operation: ECDSA sign SHA384
    0x17 - operation: ECDSA sign SHA512
    0x18 - operation: Ed25519 sign
    0x23 - operation: RPC
    0x24 - operation: Custom Function
    0x35 - operation: RSASSA-PSS sign SHA256
    0x36 - operation: RSASSA-PSS sign SHA384
    0x37 - operation: RSASSA-PSS sign SHA512
    0x41 - operation: ML-DSA-44 sign (TLS sigalg 0x0904)
    0x42 - operation: ML-DSA-65 sign (TLS sigalg 0x0905)
    0x43 - operation: ML-DSA-87 sign (TLS sigalg 0x0906)

Ed25519 sign requires an Ed25519 key; otherwise cryptography failure (0x01).

ML-DSA sign payloads are the raw TLS 1.3 server CertificateVerify signed content
(RFC 8446, Section 4.4.3), exactly 130 or 146 bytes:

    64 bytes of 0x20 || "TLS 1.3, server CertificateVerify" || 0x00 || SHA-256 or SHA-384 hash

Other payloads return format error (0x07); a key of the wrong parameter set
returns cryptography failure (0x01). The response is the raw pure ML-DSA
signature (empty context). ML-DSA keys are only used with the ML-DSA opcodes;
other sign opcodes return cryptography failure (0x01).

### Certificate usage item

Tag 0x18 selects the key by certificate usage and scope:

    Usage - 1 byte; 0x01 = service server. Other values are rejected.
    Scope - rest of the value; 1 to 64 bytes of [a-z0-9_-].

On a key operation (RSA decrypt or any sign opcode):

* an invalid usage or scope, or a non-empty Supplemental payload (0x14) or
  Certificate ID (0x06), returns format error (0x07);
* the key is selected only by usage and scope (plus SNI as applicable), never by
  SKI, Supplemental payload or Certificate ID; if none exists, or the server's
  keystore lacks certificate usage support, the server returns key not found (0x02).

Other opcodes ignore the item. Older servers skip the unknown tag and use their
normal key lookup, and return bad opcode (0x05) for 0x41-0x43.

Responses contain a header with a matching ID and only two items:

    0x11 - length: 1, data: opcode describing operation status
    0x12 - length: variable, data: payload response

The following opcodes are supported in the opcode item:

    0xF0 - operation: success, payload: modified payload
    0xFF - operation: error, payload: error payload (see immediately below)

On an error, these are the possible 1-byte payloads:

    0x01 - cryptography failure
    0x02 - key not found - no matching certificate ID
    0x03 - read error - I/O read failure
    0x04 - version mismatch - unsupported version incorrect
    0x05 - bad opcode - use of unknown opcode in request
    0x06 - unexpected opcode - use of response opcode in request
    0x07 - format error - malformed message
    0x08 - internal error - memory or other internal error

Defines and further details of the protocol can be found in [kssl.h](https://github.com/cloudflare/keyless/blob/master/kssl.h)
from the C implementation.

![Image](docs/keyless_exchange_diagram.png)