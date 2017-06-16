package protocol

import (
	"io"
)

// Respond constructs a response packet and writes it to w in the Keyless wire
// format.
func Respond(w io.Writer, id uint32, payload []byte) error {
	pkt := MakeRespondPacket(id, payload)
	_, err := pkt.WriteTo(w)
	return err
}

// RespondPong constructs a pong packet and writes it to w in the Keyless wire
// format.
func RespondPong(w io.Writer, id uint32, payload []byte) error {
	pkt := MakePongPacket(id, payload)
	_, err := pkt.WriteTo(w)
	return err
}

// RespondError constructs an error packet and writes it to w in the Keyless
// wire format.
func RespondError(w io.Writer, id uint32, err Error) error {
	pkt := MakeErrorPacket(id, err)
	_, e := pkt.WriteTo(w)
	return e
}

// MakeRespondPacket constructs a packet representing a response message.
func MakeRespondPacket(id uint32, payload []byte) Packet {
	return NewPacket(id, Operation{
		Opcode:  OpResponse,
		Payload: payload,
	})
}

// MakePongPacket constructs a packet representing a pong message.
func MakePongPacket(id uint32, payload []byte) Packet {
	return NewPacket(id, Operation{
		Opcode:  OpPong,
		Payload: payload,
	})
}

// MakeErrorPacket constructs a packet representing an error message.
func MakeErrorPacket(id uint32, err Error) Packet {
	return NewPacket(id, Operation{
		Opcode:  OpError,
		Payload: []byte{byte(err)},
	})
}
