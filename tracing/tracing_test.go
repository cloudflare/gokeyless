package tracing

import (
	"testing"

	"github.com/opentracing/opentracing-go"
	"github.com/stretchr/testify/assert"
	"github.com/uber/jaeger-client-go"
)

func TestSpanContextFromBinary(t *testing.T) {
	tracer, closer := jaeger.NewTracer("test", jaeger.NewConstSampler(true), jaeger.NewInMemoryReporter())
	defer closer.Close()
	opentracing.SetGlobalTracer(tracer)

	tests := []struct {
		name       string
		input      []byte
		wantErr    bool
		wantNilCtx bool
	}{
		{
			name:       "empty data",
			input:      nil,
			wantNilCtx: true,
		},
		{
			name: "binary data",
			input: []byte{
				0x5c, 0x17, 0x15, 0x8c, 0x70, 0x66, 0xf7, 0x69, 0x02, 0x58, 0xc6, 0x66, 0x15, 0xa4, 0x6c, 0xe7,
				0x67, 0xd4, 0x48, 0xc6, 0x92, 0x8a, 0x7d, 0x67, 0xd0, 0x79, 0xa1, 0xfc, 0xc3, 0x07, 0x02, 0xf1,
				0x03, 0x00, 0x00, 0x00, 0x00,
			},
		},
		{
			name:  "text map data",
			input: []byte("5c17158c7066f7690258c66615a46ce7:67d448c6928a7d67:d079a1fcc30702f1:3"),
		},
		{
			name:    "bad data",
			input:   []byte("bad-data"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc, err := SpanContextFromBinary(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.wantNilCtx {
					assert.Nil(t, sc)
				} else {
					assert.NotNil(t, sc)
				}
			}
		})
	}
}
