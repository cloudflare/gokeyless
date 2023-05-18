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
    0x08 - operation: RSA raw decrypt payload
    0x12 - operation: ECDSA sign MD5SHA1
    0x13 - operation: ECDSA sign SHA1
    0x14 - operation: ECDSA sign SHA224
    0x15 - operation: ECDSA sign SHA256
    0x16 - operation: ECDSA sign SHA384
    0x17 - operation: ECDSA sign SHA512
    0x23 - operation: RPC
    0x24 - operation: Custom Function
    0x35 - operation: RSASSA-PSS sign SHA256
    0x36 - operation: RSASSA-PSS sign SHA384
    0x36 - operation: RSASSA-PSS sign SHA512

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
