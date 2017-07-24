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

// MakeRespondPacket constructs a Packet representing a response message.
func MakeRespondPacket(id uint32, payload []byte) Packet { return NewPacket(id, MakeRespondOp(payload)) }

// MakePongPacket constructs a Packet representing a pong message.
func MakePongPacket(id uint32, payload []byte) Packet { return NewPacket(id, MakePongOp(payload)) }

// MakeErrorPacket constructs a Packet representing an error message.
func MakeErrorPacket(id uint32, err Error) Packet { return NewPacket(id, MakeErrorOp(err)) }

// MakeRespondOp constructs an Operation representing a response message.
func MakeRespondOp(payload []byte) Operation { return Operation{Opcode: OpResponse, Payload: payload} }

// MakePongOp constructs an Operation representing a pong message.
func MakePongOp(payload []byte) Operation { return Operation{Opcode: OpPong, Payload: payload} }

// MakeErrorOp constructs an Operation representing a error message.
func MakeErrorOp(err Error) Operation { return Operation{Opcode: OpError, Payload: []byte{byte(err)}} }
