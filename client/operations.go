package client

import (
	"bytes"
	"errors"
	"fmt"
	"net"

	"github.com/cloudflare/gokeyless"
)

// Ping requests that the server reflect the data back to the client.
func Ping(c net.Conn, data []byte) error {
	operation := &gokeyless.Operation{
		Opcode:  gokeyless.OpPing,
		Payload: data,
	}
	req := operation.Header()

	if err := gokeyless.WriteHeader(c, req); err != nil {
		return err
	}

	resp, err := gokeyless.ReadHeader(c)
	if err != nil {
		return err
	}

	if req.ID != resp.ID {
		return errors.New("ids don't match")
	}

	respOp := new(gokeyless.Operation)
	if err := respOp.UnmarshalBinary(resp.Body); err != nil {
		return err
	}

	if respOp.Opcode != gokeyless.OpPong {
		return fmt.Errorf("wrong response opcode: %v", respOp.Opcode)
	}

	if bytes.Compare(respOp.Payload, data) != 0 {
		return fmt.Errorf("payloads don't match: %v!=%v", data, respOp.Payload)
	}

	return nil
}
