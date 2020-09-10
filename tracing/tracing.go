// package tracing contains opentracing helper functions

package tracing

import (
	"bytes"
	"context"
	"fmt"
	"net/rpc"

	"github.com/cloudflare/gokeyless/protocol"
	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"
	opentracing_log "github.com/opentracing/opentracing-go/log"
)

// SpanContextFromBinary builds span context based on binary-encoded bytes (e.g. for servers)
func SpanContextFromBinary(spanData []byte) (opentracing.SpanContext, error) {
	if len(spanData) == 0 {
		// If there is no span data to decode then `Extract` will return an error, but
		// we really only want this function to return error if the span data is malformed, not empty.
		return nil, nil
	}
	var scReader = bytes.NewReader(spanData)
	return opentracing.GlobalTracer().Extract(opentracing.Binary, scReader)
}

// SpanContextToBinary returns bytes representing the binary-encoded span context (e.g. for clients)
func SpanContextToBinary(sc opentracing.SpanContext) ([]byte, error) {
	var b bytes.Buffer

	err := opentracing.GlobalTracer().Inject(sc, opentracing.Binary, &b)
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// SetOperationSpanTags sets span tags with all of the operation's fields
func SetOperationSpanTags(span opentracing.Span, op *protocol.Operation) {
	tags := map[string]interface{}{
		"operation.opcode":         op.Opcode.String(),
		"operation.ski":            op.SKI,
		"operation.digest":         fmt.Sprintf("%02x", op.Digest),
		"operation.clientip":       op.ClientIP,
		"operation.serverip":       op.ServerIP,
		"operation.sni":            op.SNI,
		"operation.certid":         op.CertID,
		"operation.customfuncname": op.CustomFuncName,
	}
	for k, v := range tags {
		span.SetTag(k, v)
	}
}

// CallRPC wraps rpc.Call with a trace
func CallRPC(ctx context.Context, rpc *rpc.Client, serviceMethod string, args interface{}, reply interface{}) error {
	span, ctx := opentracing.StartSpanFromContext(ctx, fmt.Sprintf("rpc: %s", serviceMethod))
	defer span.Finish()
	ext.SpanKind.Set(span, ext.SpanKindRPCClientEnum)
	return rpc.Call(serviceMethod, args, reply)
}

// LogError marks that an error has occurred within the scope of a span.
func LogError(span opentracing.Span, err error) {
	//set error tag to true, allows searching by `error=true`
	ext.Error.Set(span, true)

	//emit a log message, with the value containing the error message
	span.LogFields(opentracing_log.Error(err))
}
