package gokeyless

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
)

// Tag marks the type of an Item.
type Tag byte

const (
	// TagCertificateDigest implies a SHA256 digest of a key.
	TagCertificateDigest Tag = 0x01
	// TagServerName implies an SNI string.
	TagServerName = 0x02
	// TagClientIP implies an IPv4/6 address.
	TagClientIP = 0x03
	// TagOpcode implies an opcode describing operation to be performed OR operation status.
	TagOpcode = 0x11
	// TagPayload implies a payload to sign or encrypt OR payload response.
	TagPayload = 0x12
	// TagPadding implies an item with a meaningless payload added for padding.
	TagPadding = 0x20
)

// Op describing operation to be performed OR operation status.
type Op byte

const (
	// OpRSADecrypt requests an RSA decrypted payload.
	OpRSADecrypt Op = 0x01
	// OpRSADecryptRaw requests an unpadded RSA decryption of the payload.
	OpRSADecryptRaw = 0x08

	// OpRSASignMD5SHA1 requests an RSA signature on an MD5SHA1 hash payload.
	OpRSASignMD5SHA1 = 0x02
	// OpRSASignSHA1 requests an RSA signature on an SHA1 hash payload.
	OpRSASignSHA1 = 0x03
	// OpRSASignSHA224 requests an RSA signature on an SHA224 hash payload.
	OpRSASignSHA224 = 0x04
	// OpRSASignSHA256 requests an RSA signature on an SHA256 hash payload.
	OpRSASignSHA256 = 0x05
	// OpRSASignSHA384 requests an RSA signature on an SHA384 hash payload.
	OpRSASignSHA384 = 0x06
	// OpRSASignSHA512 requests an RSA signature on an SHA512 hash payload.
	OpRSASignSHA512 = 0x07

	// OpECDSASignMD5SHA1 requests an ECDSA signature on an MD5SHA1 hash payload.
	OpECDSASignMD5SHA1 = 0x12
	// OpECDSASignSHA1 requests an ECDSA signature on an SHA1 hash payload.
	OpECDSASignSHA1 = 0x13
	// OpECDSASignSHA224 requests an ECDSA signature on an SHA224 hash payload.
	OpECDSASignSHA224 = 0x14
	// OpECDSASignSHA256 requests an ECDSA signature on an SHA256 hash payload.
	OpECDSASignSHA256 = 0x15
	// OpECDSASignSHA384 requests an ECDSA signature on an SHA384 hash payload.
	OpECDSASignSHA384 = 0x16
	// OpECDSASignSHA512 requests an ECDSA signature on an SHA512 hash payload.
	OpECDSASignSHA512 = 0x17

	// OpPing indicates a test message which will be echoed with opcode changed to OpPong.
	OpPing = 0xF1
	// OpPong indicates a response echoed from an OpPing test message.
	OpPong = 0xF2

	// OpResponse is used to send a block of data back to the client.
	OpResponse = 0xF0
	// OpError indicates some error has occurred, explanation is single byte in payload.
	OpError = 0xFF
)

// Error defines a 1-byte error payload.
type Error byte

const (
	// ErrCrypto indicates a cryptography failure.
	ErrCrypto Error = 0x01
	// ErrKeyNotFound indicates no matching certificate ID.
	ErrKeyNotFound = 0x02
	// ErrRead indicates a disk read failure.
	ErrRead = 0x03
	// ErrVersionMismatch indicates an unsupported or incorrect version.
	ErrVersionMismatch = 0x04
	// ErrBadOpcode indicates use of unknown opcode in request.
	ErrBadOpcode = 0x05
	// ErrUnexpectedOpcode indicates use of response opcode in request.
	ErrUnexpectedOpcode = 0x06
	// ErrFormat indicates a malformed message.
	ErrFormat = 0x07
	// ErrInternal indicates an internal error.
	ErrInternal = 0x08
)

const (
	paddedLength = 1024
	headerSize   = 8
)

// Header represents the format for a Keyless protocol header.
type Header struct {
	MajorVers, MinorVers uint8
	ID                   uint32
	// Length of marshaled Body. Only used in unmarshaling.
	Length uint16
	Body   *Operation
}

// NewHeader returns a new Header from a sequence of Items.
func NewHeader(operation *Operation) *Header {
	return &Header{
		MajorVers: 0x01,
		MinorVers: 0x00,
		ID:        rand.Uint32(),
		Body:      operation,
	}
}

// MarshalBinary header into on-the-wire format.
func (h *Header) MarshalBinary() ([]byte, error) {
	data := make([]byte, 8)
	body, err := h.Body.MarshalBinary()
	if err != nil {
		return nil, err
	}
	data[0] = h.MajorVers
	data[1] = h.MinorVers
	binary.BigEndian.PutUint16(data[2:4], uint16(len(body)))
	binary.BigEndian.PutUint32(data[4:8], h.ID)
	return append(data, body...), nil
}

// UnmarshalBinary header from on-the-wire format.
func (h *Header) UnmarshalBinary(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("header data incomplete (only %d bytes)", len(data))
	}

	h.MajorVers = data[0]
	h.MinorVers = data[1]
	h.Length = binary.BigEndian.Uint16(data[2:4])
	h.ID = binary.BigEndian.Uint32(data[4:8])
	return nil
}

// Operation defines a single (repeatable) keyless operation.
type Operation struct {
	Opcode   Op
	Payload  []byte
	Dgst     Digest
	ClientIP net.IP
	SNI      string
}

// tlvBytes returns the byte representation of a Tag-Length-Value item.
func tlvBytes(tag Tag, data []byte) []byte {
	b := make([]byte, 3)
	b[0] = byte(tag)
	binary.BigEndian.PutUint16(b[1:3], uint16(len(data)))
	return append(b, data...)
}

// MarshalBinary returns a binary
func (o *Operation) MarshalBinary() ([]byte, error) {
	var b []byte

	b = append(b, tlvBytes(TagOpcode, []byte{byte(o.Opcode)})...)

	if len(o.Payload) > 0 {
		b = append(b, tlvBytes(TagPayload, o.Payload)...)
	}

	if o.Dgst != emptyDigest {
		b = append(b, tlvBytes(TagCertificateDigest, o.Dgst[:])...)
	}

	if o.ClientIP != nil {
		ip := o.ClientIP.To4()
		if ip == nil {
			ip = o.ClientIP
		}
		b = append(b, tlvBytes(TagClientIP, ip)...)
	}

	if o.SNI != "" {
		b = append(b, tlvBytes(TagServerName, []byte(o.SNI))...)
	}

	if len(b)+headerSize < paddedLength {
		padding := make([]byte, paddedLength-(len(b)+headerSize))
		b = append(b, tlvBytes(TagPadding, padding)...)
	}
	return b, nil
}

// UnmarshalBinary unmarshals a binary-encoded TLV list of items into an Operation.
func (o *Operation) UnmarshalBinary(body []byte) error {
	var length int
	seen := make(map[Tag]bool)
	for i := 0; i+2 < len(body); i += 3 + length {
		tag := Tag(body[i])

		length = int(binary.BigEndian.Uint16(body[i+1 : i+3]))
		if i+3+length > len(body) {
			return fmt.Errorf("length (%d) longer than body", length)
		}

		data := body[i+3 : i+3+length]

		if seen[tag] {
			return fmt.Errorf("tag %v seen multiple times", tag)
		}
		seen[tag] = true

		switch tag {
		case TagOpcode:
			if len(data) != 1 {
				return fmt.Errorf("invalid opcode: %v", data)
			}
			o.Opcode = Op(data[0])

		case TagPayload:
			o.Payload = data

		case TagCertificateDigest:
			if len(data) != len(emptyDigest) {
				return fmt.Errorf("invalid digest length: %d", len(data))
			}
			copy(o.Dgst[:], data)

		case TagClientIP:
			o.ClientIP = data

		case TagServerName:
			o.SNI = string(data)

		case TagPadding:
			// ignore padding
		default:
			return fmt.Errorf("unknown tag: %v", tag)
		}
	}
	return nil
}

// GetError returns string errors associated with error response codes.
func (o *Operation) GetError() error {
	var errStr string
	if o.Opcode != OpError || len(o.Payload) != 1 {
		errStr = "no error"
	} else {
		switch Error(o.Payload[0]) {
		case ErrCrypto:
			errStr = "cryptography error"
		case ErrKeyNotFound:
			errStr = "no matching certificate digest"
		case ErrRead:
			errStr = "disk read failure"
		case ErrVersionMismatch:
			errStr = "version mismatch"
		// ErrBadOpcode indicates use of unknown opcode in request.
		case ErrBadOpcode:
			errStr = "bad opcode"
		case ErrUnexpectedOpcode:
			errStr = "unexpected opcode"
		case ErrFormat:
			errStr = "malformed message"
		case ErrInternal:
			errStr = "internal error"
		default:
			errStr = "unknown error"
		}
	}
	return errors.New("keyless: " + errStr)
}

// Digest represents a certificate digest used to index remote keys.
type Digest [sha256.Size]byte

var emptyDigest Digest
