package conn

import (
	"bytes"
	"context"
	"encoding/gob"
	"fmt"
	"io"
	"net/rpc"

	"github.com/cloudflare/gokeyless/protocol"
)

// RPC returns an RPC client which uses the connection. Closing the returned
// *rpc.Client will cleanup any spawned goroutines, but will not close the
// underlying connection.
func (c *Conn) RPC() *rpc.Client {
	pr, pw := io.Pipe()
	codec := &clientCodec{c, pr, pw, nil}

	return rpc.NewClientWithCodec(codec)
}

// clientCodec implements net/rpc.ClientCodec over a connection to a gokeyless
// server.
type clientCodec struct {
	conn *Conn

	pr  *io.PipeReader
	pw  *io.PipeWriter
	dec *gob.Decoder
}

func (cc *clientCodec) WriteRequest(req *rpc.Request, body interface{}) error {
	buff := &bytes.Buffer{}
	enc := gob.NewEncoder(buff)

	if err := enc.Encode(req); err != nil {
		return fmt.Errorf("WriteRequest: %w", err)
	} else if err := enc.Encode(body); err != nil {
		return fmt.Errorf("WriteRequest: %w", err)
	}

	result, err := cc.conn.sendOp(context.Background(), protocol.Operation{
		Opcode:  protocol.OpRPC,
		Payload: buff.Bytes(),
	})
	if err != nil {
		return fmt.Errorf("WriteRequest: %w", err)
	}
	go cc.processResponse(result, req)

	return nil
}

func (cc *clientCodec) processResponse(response chan *result, req *rpc.Request) {
	res := <-response
	if res == nil {
		fmt.Printf("closing writer")
		cc.pw.Close()
		return
	}
	if res.err != nil {
		synthesizeError(cc.pw, req, res.err)
		return
	}
	if res.op.Opcode == protocol.OpError {
		synthesizeError(cc.pw, req, res.op.GetError())
		return
	}
	_, _ = cc.pw.Write(res.op.Payload)
}

func synthesizeError(w io.Writer, req *rpc.Request, err error) {
	resp := &rpc.Response{
		ServiceMethod: req.ServiceMethod,
		Seq:           req.Seq,
		Error:         err.Error(),
	}
	enc := gob.NewEncoder(w)
	_ = enc.Encode(resp)
	_ = enc.Encode(0) // Send empty value to feed the reader
}

func (cc *clientCodec) ReadResponseHeader(res *rpc.Response) error {
	// gob decoders are stateful but we encode statelessly, so we need to reset
	// the decoder after every full read.
	cc.dec = gob.NewDecoder(cc.pr)
	return cc.dec.Decode(res)
}

func (cc *clientCodec) ReadResponseBody(body interface{}) error {
	return cc.dec.Decode(body)
}

func (cc *clientCodec) Close() error {
	return cc.pr.Close()
}
