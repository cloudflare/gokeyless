package gokeyless

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
)

// Tag marks the type of an Item.
type Tag byte

const (
	// TagCertificateDigest implies a SHA256 Digest of a key.
	TagCertificateDigest Tag = 0x01
	// TagServerName implies an SNI string.
	TagServerName Tag = 0x02
	// TagClientIP implies an IPv4/6 address.
	TagClientIP = 0x03
	// TagSubjectKeyIdentifier implies the Subject Key Identifier for the given key
	TagSubjectKeyIdentifier = 0x04
	// TagOpcode implies an opcode describing operation to be performed OR operation status.
	TagOpcode = 0x11
	// TagPayload implies a payload to sign or encrypt OR payload response.
	TagPayload = 0x12
	// TagPadding implies an item with a meaningless payload added for padding.
	TagPadding = 0x20
)

func (t Tag) String() string {
	switch t {
	case TagCertificateDigest:
		return "TagCertificateDigest"
	case TagServerName:
		return "TagServerName"
	case TagClientIP:
		return "TagClientIP"
	case TagSubjectKeyIdentifier:
		return "TagSubjectKeyIdentifier"
	case TagOpcode:
		return "TagOpcode"
	case TagPayload:
		return "TagPayload"
	case TagPadding:
		return "TagPadding"
	default:
		return fmt.Sprintf("Invalid (%02x)", byte(t))
	}
}

// Op describing operation to be performed OR operation status.
type Op byte

const (
	// OpRSADecrypt requests an RSA decrypted payload.
	OpRSADecrypt Op = 0x01
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

func (o Op) String() string {
	switch o {
	case OpRSADecrypt:
		return "OpRSADecrypt"
	case OpRSASignMD5SHA1:
		return "OpRSASignMD5SHA1"
	case OpRSASignSHA1:
		return "OpRSASignSHA1"
	case OpRSASignSHA224:
		return "OpRSASignSHA224"
	case OpRSASignSHA256:
		return "OpRSASignSHA256"
	case OpRSASignSHA384:
		return "OpRSASignSHA384"
	case OpRSASignSHA512:
		return "OpRSASignSHA512"
	case OpECDSASignMD5SHA1:
		return "OpECDSASignMD5SHA1"
	case OpECDSASignSHA1:
		return "OpECDSASignSHA1"
	case OpECDSASignSHA224:
		return "OpECDSASignSHA224"
	case OpECDSASignSHA256:
		return "OpECDSASignSHA256"
	case OpECDSASignSHA384:
		return "OpECDSASignSHA384"
	case OpECDSASignSHA512:
		return "OpECDSASignSHA512"
	case OpPing:
		return "OpPing"
	case OpPong:
		return "OpPong"
	case OpResponse:
		return "OpResponse"
	case OpError:
		return "OpError"
	default:
		return fmt.Sprintf("Invalid (%02x)", byte(o))
	}
}

// Error defines a 1-byte error payload.
type Error byte

const (
	// ErrCrypto indicates a cryptography failure.
	ErrCrypto Error = iota + 1
	// ErrKeyNotFound indicates no matching certificate ID.
	ErrKeyNotFound
	// ErrRead indicates a disk read failure.
	ErrRead
	// ErrVersionMismatch indicates an unsupported or incorrect version.
	ErrVersionMismatch
	// ErrBadOpcode indicates use of unknown opcode in request.
	ErrBadOpcode
	// ErrUnexpectedOpcode indicates use of response opcode in request.
	ErrUnexpectedOpcode
	// ErrFormat indicates a malformed message.
	ErrFormat
	// ErrInternal indicates an internal error.
	ErrInternal
)

func (e Error) Error() string {
	var errStr string
	switch e {
	case ErrCrypto:
		errStr = "cryptography error"
	case ErrKeyNotFound:
		errStr = "no matching certificate SKI"
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
	return "keyless: " + errStr
}

const (
	paddedLength = 1024
	headerSize   = 8
)

// SKI represents a subject key identifier used to index remote keys.
type SKI [sha1.Size]byte

var nilSKI SKI

// Valid compares an SKI to 0 to determine if it is valid.
func (ski SKI) Valid() bool {
	return !bytes.Equal(ski[:], nilSKI[:])
}

// GetSKI returns the SKI of a public key.
func GetSKI(pub crypto.PublicKey) (SKI, error) {
	encodedPub, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nilSKI, err
	}

	subPKI := new(struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	})

	_, err = asn1.Unmarshal(encodedPub, subPKI)
	if err != nil {
		return nilSKI, err
	}

	return sha1.Sum(subPKI.SubjectPublicKey.Bytes), nil
}

// Digest represents a SHA-256 digest of an RSA public key modulus
type Digest [sha256.Size]byte

var nilDigest Digest

// Valid compares a digest to 0 to determine if it is valid.
func (digest Digest) Valid() bool {
	return !bytes.Equal(digest[:], nilDigest[:])
}

// GetDigest returns the digest of an RSA public key.
func GetDigest(pub crypto.PublicKey) (Digest, bool) {
	if rsaPub, ok := pub.(*rsa.PublicKey); ok {
		return sha256.Sum256([]byte(fmt.Sprintf("%X", rsaPub.N))), true
	}
	return nilDigest, false
}

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
	SKI      SKI
	Digest   Digest
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

	if o.SKI.Valid() {
		b = append(b, tlvBytes(TagSubjectKeyIdentifier, o.SKI[:])...)
	}

	if o.Digest.Valid() {
		b = append(b, tlvBytes(TagCertificateDigest, o.Digest[:])...)
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
			return fmt.Errorf("tag %s seen multiple times", tag)
		}
		seen[tag] = true

		switch tag {
		case TagOpcode:
			if len(data) != 1 {
				return fmt.Errorf("invalid opcode: %s", data)
			}
			o.Opcode = Op(data[0])

		case TagPayload:
			o.Payload = data

		case TagSubjectKeyIdentifier:
			if len(data) == sha1.Size {
				copy(o.SKI[:], data)
			}

		case TagCertificateDigest:
			if len(data) == sha256.Size {
				copy(o.Digest[:], data)
			}

		case TagClientIP:
			o.ClientIP = data

		case TagServerName:
			o.SNI = string(data)

		case TagPadding:
			// ignore padding
		default:
			return fmt.Errorf("unknown tag: %s", tag)
		}
	}
	return nil
}

// GetError returns string errors associated with error response codes.
func (o *Operation) GetError() error {
	if o.Opcode != OpError || len(o.Payload) != 1 {
		return errors.New("keyless: no error")
	}
	return Error(o.Payload[0])
}
