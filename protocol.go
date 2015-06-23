package gokeyless

import (
	"crypto/sha256"
	"encoding/binary"
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
	Length               uint16
	ID                   uint32
	Body                 []byte
}

// NewHeader returns a new Header from a sequence of Items.
func NewHeader(items []*Item) *Header {
	var body []byte
	for _, item := range items {
		b, _ := item.MarshalBinary()
		body = append(body, b...)
	}

	length := headerSize + len(body)
	if length < paddedLength {
		b, _ := NewPadding(paddedLength - length).MarshalBinary()
		body = append(body, b...)
	}

	return &Header{
		MajorVers: 0x01,
		MinorVers: 0x00,
		Length:    uint16(len(body)),
		ID:        rand.Uint32(),
		Body:      body,
	}
}

// MarshalBinary header into on-the-wire format.
func (h *Header) MarshalBinary() ([]byte, error) {
	data := make([]byte, 8)
	data[0] = h.MajorVers
	data[1] = h.MinorVers
	binary.BigEndian.PutUint16(data[2:4], h.Length)
	binary.BigEndian.PutUint32(data[4:8], h.ID)
	return append(data, h.Body...), nil
}

// UnmarshalBinary header from on-the-wire format.
func (h *Header) UnmarshalBinary(data []byte) error {
	h.MajorVers = data[0]
	h.MinorVers = data[1]
	h.Length = binary.BigEndian.Uint16(data[2:4])
	h.ID = binary.BigEndian.Uint32(data[4:8])
	return nil
}

// Item represents an actual Keyless protocol value being passed.
type Item struct {
	Tag  Tag
	Data []byte
}

// NewPadding returns an item to be used for padding.
func NewPadding(size int) *Item {
	return &Item{TagPadding, make([]byte, size)}
}

// UnmarshalItems reads items from their TLV serialized format.
func UnmarshalItems(body []byte) (items []*Item, err error) {
	var length int
	for i := 0; i+2 < len(body); i += 3 + length {
		length = int(binary.BigEndian.Uint16(body[i+1 : i+3]))
		if i+3+length > len(body) {
			err = fmt.Errorf("length (%d) longer than body", length)
			return
		}
		tag := Tag(body[i])
		switch tag {
		case TagCertificateDigest:
		case TagServerName:
		case TagClientIP:
		case TagOpcode:
		case TagPayload:
		case TagPadding:
			continue
		default:
			continue
		}
		items = append(items, &Item{tag, body[i+3 : i+3+length]})
	}
	return
}

// Operation defines a single (repeatable) keyless operation.
type Operation struct {
	Opcode   Op
	Payload  []byte
	Dgst     Digest
	ClientIP net.IP
	SNI      string
}

// Header returns a new header corresponding to the operation
func (o *Operation) Header() *Header {
	var items []*Item

	items = append(items, &Item{TagOpcode, []byte{byte(o.Opcode)}})

	if len(o.Payload) > 0 {
		items = append(items, &Item{TagPayload, o.Payload})
	}

	if o.Dgst != emptyDigest {
		items = append(items, &Item{TagCertificateDigest, o.Dgst[:]})
	}

	if o.ClientIP != nil {
		ip := o.ClientIP.To4()
		if ip == nil {
			ip = o.ClientIP
		}
		items = append(items, &Item{TagClientIP, ip})
	}

	if o.SNI != "" {
		items = append(items, &Item{TagServerName, []byte(o.SNI)})
	}

	return NewHeader(items)
}

// UnmarshalBinary unmarshals a binary-encoded TLV list of items into an Operation.
func (o *Operation) UnmarshalBinary(body []byte) error {
	items, err := UnmarshalItems(body)
	if err != nil {
		return err
	}

	seen := make(map[Tag]bool)
	for _, item := range items {
		if seen[item.Tag] {
			return fmt.Errorf("tag %v seen multiple times", item.Tag)
		}
		seen[item.Tag] = true
		switch item.Tag {
		case TagOpcode:
			if len(item.Data) != 1 {
				return fmt.Errorf("invalid opcode: %v", item.Data)
			}
			o.Opcode = Op(item.Data[0])
		case TagPayload:
			o.Payload = item.Data
		case TagCertificateDigest:
			if len(item.Data) != len(emptyDigest) {
				return fmt.Errorf("invalid digest: %v", item.Data)
			}
			copy(o.Dgst[:], item.Data)
		case TagClientIP:
			o.ClientIP = item.Data
		case TagServerName:
			o.SNI = string(item.Data)
		case TagPadding:
		default:
			return fmt.Errorf("unknown tag: %v", item.Tag)
		}
	}

	return nil
}

// MarshalBinary item into on-the-wire format
func (i *Item) MarshalBinary() ([]byte, error) {
	data := make([]byte, 3)
	data[0] = byte(i.Tag)
	binary.BigEndian.PutUint16(data[1:], uint16(len(i.Data)))
	return append(data, i.Data...), nil
}

// Digest represents a certificate digest used to index remote keys.
type Digest [sha256.Size]byte

var emptyDigest Digest

// WriteHeader marshals and header and writes it to the conn.
func WriteHeader(c net.Conn, header *Header) error {
	b, err := header.MarshalBinary()
	if err != nil {
		return err
	}
	_, err = c.Write(b)
	return err
}

// ReadHeader unmarhals a header from the wire into the internal Header structure.
func ReadHeader(c net.Conn) (*Header, error) {
	b := make([]byte, 8)
	if _, err := c.Read(b); err != nil {
		return nil, err
	}

	h := new(Header)
	h.UnmarshalBinary(b)
	h.Body = make([]byte, h.Length)
	_, err := c.Read(h.Body)
	return h, err
}
