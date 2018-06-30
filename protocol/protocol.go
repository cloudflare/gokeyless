package protocol

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
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net"

	"github.com/cloudflare/cfssl/helpers"
)

//go:generate stringer -type=Tag,Op -output=protocol_string.go

// Tag marks the type of an Item.
type Tag byte

const (
	// TagCertificateDigest implies a SHA256 Digest of a key.
	TagCertificateDigest Tag = 0x01
	// TagServerName implies server hostname (SNI) for the proxyed TLS server.
	TagServerName Tag = 0x02
	// TagClientIP implies an IPv4/6 address of the client connecting.
	TagClientIP Tag = 0x03
	// TagSubjectKeyIdentifier implies the Subject Key Identifier for the given key.
	TagSubjectKeyIdentifier Tag = 0x04
	// TagServerIP implies an IPv4/6 address of the proxyed TLS server.
	TagServerIP Tag = 0x05
	// TagOpcode implies an opcode describing operation to be performed OR operation status.
	TagOpcode Tag = 0x11
	// TagPayload implies a payload to sign or encrypt OR payload response.
	TagPayload Tag = 0x12
	// TagPadding implies an item with a meaningless payload added for padding.
	TagPadding Tag = 0x20
)

// Op describing operation to be performed OR operation status.
type Op byte

const (
	// OpRSADecrypt requests an RSA decrypted payload.
	OpRSADecrypt Op = 0x01
	// OpRSASignMD5SHA1 requests an RSA signature on an MD5SHA1 hash payload.
	OpRSASignMD5SHA1 Op = 0x02
	// OpRSASignSHA1 requests an RSA signature on an SHA1 hash payload.
	OpRSASignSHA1 Op = 0x03
	// OpRSASignSHA224 requests an RSA signature on an SHA224 hash payload.
	OpRSASignSHA224 Op = 0x04
	// OpRSASignSHA256 requests an RSA signature on an SHA256 hash payload.
	OpRSASignSHA256 Op = 0x05
	// OpRSASignSHA384 requests an RSA signature on an SHA384 hash payload.
	OpRSASignSHA384 Op = 0x06
	// OpRSASignSHA512 requests an RSA signature on an SHA512 hash payload.
	OpRSASignSHA512 Op = 0x07

	// OpRSAPSSSignSHA256 requests an RSASSA-PSS signature on an SHA256 hash payload.
	OpRSAPSSSignSHA256 Op = 0x35
	// OpRSAPSSSignSHA384 requests an RSASSA-PSS signature on an SHA384 hash payload.
	OpRSAPSSSignSHA384 Op = 0x36
	// OpRSAPSSSignSHA512 requests an RSASSA-PSS signature on an SHA512 hash payload.
	OpRSAPSSSignSHA512 Op = 0x37

	// OpECDSASignMD5SHA1 requests an ECDSA signature on an MD5SHA1 hash payload.
	OpECDSASignMD5SHA1 Op = 0x12
	// OpECDSASignSHA1 requests an ECDSA signature on an SHA1 hash payload.
	OpECDSASignSHA1 Op = 0x13
	// OpECDSASignSHA224 requests an ECDSA signature on an SHA224 hash payload.
	OpECDSASignSHA224 Op = 0x14
	// OpECDSASignSHA256 requests an ECDSA signature on an SHA256 hash payload.
	OpECDSASignSHA256 Op = 0x15
	// OpECDSASignSHA384 requests an ECDSA signature on an SHA384 hash payload.
	OpECDSASignSHA384 Op = 0x16
	// OpECDSASignSHA512 requests an ECDSA signature on an SHA512 hash payload.
	OpECDSASignSHA512 Op = 0x17

	// OpSeal asks to encrypt a blob (like a Session Ticket)
	OpSeal Op = 0x21
	// OpUnseal asks to decrypt a blob encrypted by OpSeal
	OpUnseal Op = 0x22
	// OpRPC executes an arbitrary exported function on the server.
	OpRPC Op = 0x23

	// OpPing indicates a test message which will be echoed with opcode changed to OpPong.
	OpPing Op = 0xF1
	// OpPong indicates a response echoed from an OpPing test message.
	OpPong Op = 0xF2

	// OpResponse is used to send a block of data back to the client.
	OpResponse Op = 0xF0
	// OpError indicates some error has occurred, explanation is single byte in payload.
	OpError Op = 0xFF
)

// Error defines a 1-byte error payload.
type Error byte

const (
	// ErrNone indicates no error occurred.
	ErrNone Error = iota
	// ErrCrypto indicates a cryptography failure.
	ErrCrypto
	// ErrKeyNotFound indicates key can't be found using the operation packet.
	ErrKeyNotFound
	// ErrRead indicates I/O read failure.
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
	// ErrCertNotFound indicates missing certificate.
	ErrCertNotFound
	// ErrExpired indicates that the sealed blob is no longer unsealable.
	ErrExpired
)

func (e Error) Error() string {
	return "keyless: " + e.String()
}

func (e Error) String() string {
	switch e {
	case ErrNone:
		return "no error"
	case ErrCrypto:
		return "cryptography error"
	case ErrKeyNotFound:
		return "key not found due to no matching SKI/SNI/ServerIP"
	case ErrRead:
		return "read failure"
	case ErrVersionMismatch:
		return "version mismatch"
	case ErrBadOpcode:
		return "bad opcode"
	case ErrUnexpectedOpcode:
		return "unexpected opcode"
	case ErrFormat:
		return "malformed message"
	case ErrInternal:
		return "internal error"
	case ErrCertNotFound:
		return "certificate not found"
	case ErrExpired:
		return "sealing key expired"
	default:
		return "unknown error"
	}
}

const (
	paddedLength = 1024
	headerSize   = 8
)

// SKI represents a subject key identifier used to index remote keys.
type SKI [sha1.Size]byte

var nilSKI SKI

// String returns a hex encoded SKI string.
func (ski SKI) String() string {
	return hex.EncodeToString(ski[:])
}

// Valid compares an SKI to 0 to determine if it is valid.
func (ski SKI) Valid() bool {
	return ski != nilSKI
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

	if _, err := asn1.Unmarshal(encodedPub, subPKI); err != nil {
		return nilSKI, err
	}

	return sha1.Sum(subPKI.SubjectPublicKey.Bytes), nil
}

// GetSKICert returns the SKI of a parsed X.509 Certificate.
func GetSKICert(cert *x509.Certificate) (SKI, error) {
	return GetSKI(cert.PublicKey)
}

// GetSKICertPEM returns the SKI of a PEM encoded X.509 Certificate.
func GetSKICertPEM(certPEM []byte) (SKI, error) {
	cert, err := helpers.ParseCertificatePEM(certPEM)
	if err != nil {
		return nilSKI, err
	}
	return GetSKICert(cert)
}

// Digest represents a SHA-256 digest of an RSA public key modulus
type Digest [sha256.Size]byte

var nilDigest Digest

// Valid compares a digest to 0 to determine if it is valid.
func (digest Digest) Valid() bool {
	return !bytes.Equal(digest[:], nilDigest[:])
}

// GetDigest returns the digest of an RSA public key.
func GetDigest(pub crypto.PublicKey) (Digest, error) {
	if rsaPub, ok := pub.(*rsa.PublicKey); ok {
		return sha256.Sum256([]byte(fmt.Sprintf("%X", rsaPub.N))), nil
	}

	return nilDigest, errors.New("can't compute digest for non-RSA public key")
}

// Header represents the header of a Keyless protocol message.
type Header struct {
	MajorVers, MinorVers uint8
	Length               uint16
	ID                   uint32
}

// MarshalBinary marshals h into its wire format. It will never return an error.
func (h *Header) MarshalBinary() ([]byte, error) {
	data := make([]byte, 8)
	data[0] = h.MajorVers
	data[1] = h.MinorVers
	binary.BigEndian.PutUint16(data[2:4], h.Length)
	binary.BigEndian.PutUint32(data[4:8], h.ID)
	return data, nil
}

// UnmarshalBinary parses data as a header stored in its wire format.
func (h *Header) UnmarshalBinary(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("cannot unmarshal into header: got %v bytes; need 8", len(data))
	}
	h.MajorVers = data[0]
	h.MinorVers = data[1]
	h.Length = binary.BigEndian.Uint16(data[2:4])
	h.ID = binary.BigEndian.Uint32(data[4:8])
	return nil
}

// WriteTo serializes h in its wire format into w.
func (h *Header) WriteTo(w io.Writer) (n int64, err error) {
	var data [8]byte
	data[0] = h.MajorVers
	data[1] = h.MinorVers
	binary.BigEndian.PutUint16(data[2:4], h.Length)
	binary.BigEndian.PutUint32(data[4:8], h.ID)
	nn, err := w.Write(data[:])
	return int64(nn), err
}

// ReadFrom deserializes into h from its wire format read from r.
func (h *Header) ReadFrom(r io.Reader) (n int64, err error) {
	var hdr [8]byte
	nn, err := io.ReadFull(r, hdr[:])
	if err != nil {
		return int64(nn), err
	}
	h.MajorVers = hdr[0]
	h.MinorVers = hdr[1]
	h.Length = binary.BigEndian.Uint16(hdr[2:4])
	h.ID = binary.BigEndian.Uint32(hdr[4:8])
	return 8, nil
}

// Packet represents the format for a Keyless protocol header and body.
type Packet struct {
	Header
	Operation
}

// NewPacket constructs a new packet with the given ID and Operation. The
// MajorVers, MinorVers, and Length fields are set automatically.
func NewPacket(id uint32, op Operation) Packet {
	return Packet{
		Header: Header{
			MajorVers: 0x01,
			MinorVers: 0x00,
			ID:        id,
			Length:    op.Bytes(),
		},
		Operation: op,
	}
}

// MarshalBinary serializes p into its wire format.
func (p *Packet) MarshalBinary() ([]byte, error) {
	hdr, err := p.Header.MarshalBinary()
	if err != nil {
		panic(fmt.Sprintf("unexpected internal error: %v", err))
	}
	body, err := p.Operation.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return append(hdr, body...), nil
}

// UnmarshalBinary deserializes into p from its wire format.
func (p *Packet) UnmarshalBinary(data []byte) error {
	err := p.Header.UnmarshalBinary(data)
	if err != nil {
		return err
	}
	// since h.Header.UnmarshalBinary succeeded, we know len(data) >= 8
	return p.Operation.UnmarshalBinary(data[8:])
}

// WriteTo serializes p in its wire format into w.
func (p *Packet) WriteTo(w io.Writer) (n int64, err error) {
	n, err = p.Header.WriteTo(w)
	if err != nil {
		return n, err
	}
	nn, err := p.Operation.WriteTo(w)
	n += nn
	return n, err
}

// ReadFrom deserializes into p from its wire format read from r.
func (p *Packet) ReadFrom(r io.Reader) (n int64, err error) {
	n, err = p.Header.ReadFrom(r)
	if err != nil {
		return n, err
	}
	body := make([]byte, int(p.Length))
	nn, err := io.ReadFull(r, body)
	n += int64(nn)
	if err != nil {
		return n, err
	}
	return n, p.Operation.UnmarshalBinary(body)
}

// Operation defines a single (repeatable) keyless operation.
type Operation struct {
	Opcode   Op
	Payload  []byte
	SKI      SKI
	Digest   Digest
	ClientIP net.IP
	ServerIP net.IP
	SNI      string
}

func (o *Operation) String() string {
	return fmt.Sprintf("[Opcode: %v, SKI: %v, Digest: %02x, Client IP: %s, Server IP: %s, SNI: %s]",
		o.Opcode,
		o.SKI,
		o.Digest,
		o.ClientIP,
		o.ServerIP,
		o.SNI,
	)
}

// tlvBytes returns the byte representation of a Tag-Length-Value item.
func tlvBytes(tag Tag, data []byte) []byte {
	b := make([]byte, 3)
	b[0] = byte(tag)
	binary.BigEndian.PutUint16(b[1:3], uint16(len(data)))
	return append(b, data...)
}

// tlvLen returns the number of bytes taken up by a TLV encoding of a blob of
// datalen bytes. It returns 3 + len(datalen).
func tlvLen(datalen int) uint16 {
	// while the uint16 field in TLV could technically handle up to three more
	// bytes, the 3-byte header would cause the total encoded bytes to exceed
	// 2^16, which would in turn overflow the Header.Length field.
	if datalen > math.MaxUint16-3 {
		panic(fmt.Sprintf("data exceeds TLV maximum length: %v", datalen))
	}
	return 3 + uint16(datalen)
}

// Bytes returns the number of bytes in o's wire format representation.
func (o *Operation) Bytes() uint16 {
	var length uint16

	add := func(l uint16) {
		if l+length < length {
			// this happens if l + length overflows uint16
			panic("wire format representation of Operation exceeds maximum length")
		}
		length += l
	}

	// opcode
	add(tlvLen(1))
	if len(o.Payload) > 0 {
		add(tlvLen(len(o.Payload)))
	}
	if o.SKI.Valid() {
		add(tlvLen(len(o.SKI[:])))
	}
	if o.Digest.Valid() {
		add(tlvLen(len(o.Digest[:])))
	}
	if o.ClientIP != nil {
		if o.ClientIP.To4() != nil {
			// IPv4
			add(tlvLen(4))
		} else {
			// IPv6
			add(tlvLen(16))
		}
	}
	if o.ServerIP != nil {
		if o.ServerIP.To4() != nil {
			// IPv4
			add(tlvLen(4))
		} else {
			// IPv6
			add(tlvLen(16))
		}
	}
	if o.SNI != "" {
		// TODO(joshlf): Is len([]byte(o.SNI)) guaranteed to be the same as len(o.SNI)?
		add(tlvLen(len([]byte(o.SNI))))
	}
	if int(length)+headerSize < paddedLength {
		// TODO: Are we sure that's the right behavior?

		// The +3 is to make room for the Tag and Length values in the TLV header.
		left := paddedLength - (int(length) + headerSize + 3)
		if left < 0 {
			// It's possible that we were within 2 or 1 bytes of the padded length,
			// in which case the 3 bytes of the TLV header take us past the end, so
			// we calculate a negative length for the padding bytes. In that case,
			// just use 0 padding bytes (and we'll go over the padding minimum by
			// 1 or 2 bytes; oh well).
			left = 0
		}

		add(tlvLen(left))
	}
	return length
}

// MarshalBinary serialises o using a TLV encoding.
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

	if o.ServerIP != nil {
		ip := o.ServerIP.To4()
		if ip == nil {
			ip = o.ServerIP
		}
		b = append(b, tlvBytes(TagServerIP, ip)...)
	}

	if o.SNI != "" {
		b = append(b, tlvBytes(TagServerName, []byte(o.SNI))...)
	}

	if len(b)+headerSize < paddedLength {
		// TODO: Are we sure that's the right behavior?

		// The +3 is to make room for the Tag and Length values in the TLV header.
		left := paddedLength - (len(b) + headerSize + 3)
		if left < 0 {
			// It's possible that we were within 2 or 1 bytes of the padded length,
			// in which case the 3 bytes of the TLV header take us past the end, so
			// we calculate a negative length for the padding bytes. In that case,
			// just use 0 padding bytes (and we'll go over the padding minimum by
			// 1 or 2 bytes; oh well).
			left = 0
		}

		padding := make([]byte, left)
		b = append(b, tlvBytes(TagPadding, padding)...)
	}
	return b, nil
}

// UnmarshalBinary unmarshals a binary-encoded TLV list of items into o.
// It guarantees that ClientIP and ServerIP, if present, are each 4 or 16 bytes.
func (o *Operation) UnmarshalBinary(body []byte) error {
	// seen has enough entires to be indexed by any valid Tag value. If more tags
	// are added later, change this code!
	var seen [33]bool
	var length int

	validateIP := func(ip net.IP) (net.IP, error) {
		if len(ip) != 4 && len(ip) != 16 {
			return nil, fmt.Errorf("invalid byte length for IP address: %v", len(ip))
		}
		return ip, nil
	}

	for i := 0; i+2 < len(body); i += 3 + length {
		tag := Tag(body[i])

		length = int(binary.BigEndian.Uint16(body[i+1 : i+3]))
		if i+3+length > len(body) {
			return fmt.Errorf("%02x length is %dB beyond end of body", tag, i+3+length-len(body))
		}

		data := body[i+3 : i+3+length]

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
			ip, err := validateIP(data)
			if err != nil {
				return fmt.Errorf("malformed client IP: %v", err)
			}
			o.ClientIP = ip
		case TagServerIP:
			ip, err := validateIP(data)
			if err != nil {
				return fmt.Errorf("malformed server IP: %v", err)
			}
			o.ServerIP = ip
		case TagServerName:
			o.SNI = string(data)
		case TagPadding:
			// ignore padding
		default:
			return fmt.Errorf("unknown tag: %02x", tag)
		}

		// only use tag as an index in seen after we've validated that it's a tag
		// that we recognize, and thus won't be out of bounds.
		if seen[tag] {
			return fmt.Errorf("tag %02x seen multiple times", tag)
		}
		seen[tag] = true
	}
	return nil
}

// WriteTo serializes o in its wire format into w.
func (o *Operation) WriteTo(w io.Writer) (n int64, err error) {
	buf, err := o.MarshalBinary()
	if err != nil {
		return 0, err
	}
	nn, err := w.Write(buf)
	n = int64(nn)
	return n, err
}

// TODO(joshlf): Should GetError return nil if o.Opcode != OpError?

// GetError returns string errors associated with error response codes.
func (o *Operation) GetError() error {
	if o.Opcode != OpError || len(o.Payload) != 1 {
		return errors.New("keyless: no error")
	}
	return Error(o.Payload[0])
}
