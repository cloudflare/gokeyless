package tracing

import (
	"strings"
	"testing"

	"github.com/cloudflare/gokeyless/protocol"
	"github.com/opentracing/opentracing-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// spanTags runs SetOperationSpanTags on a fresh sampled jaeger span and returns
// the resulting tags.
func spanTags(t *testing.T, op *protocol.Operation) opentracing.Tags {
	t.Helper()
	tracer, closer := jaeger.NewTracer("test", jaeger.NewConstSampler(true), jaeger.NewInMemoryReporter())
	defer func() { _ = closer.Close() }()
	span := tracer.StartSpan("op")
	defer span.Finish()
	SetOperationSpanTags(span, op)
	js, ok := span.(*jaeger.Span)
	require.True(t, ok)
	return js.Tags()
}

func TestSetOperationSpanTagsCertUsage(t *testing.T) {
	tests := []struct {
		name      string
		cu        *protocol.CertUsage
		wantUsage string
		wantScope string
	}{
		{
			name:      "valid",
			cu:        &protocol.CertUsage{Usage: protocol.CertUsageServiceServer, Scope: "svc-a_1"},
			wantUsage: "CertUsageServiceServer",
			wantScope: "svc-a_1",
		},
		{
			name:      "invalid scope characters",
			cu:        &protocol.CertUsage{Usage: protocol.CertUsageServiceServer, Scope: "Evil\n<script>"},
			wantUsage: "CertUsageServiceServer",
			wantScope: "invalid",
		},
		{
			name:      "scope too long",
			cu:        &protocol.CertUsage{Usage: protocol.CertUsageServiceServer, Scope: strings.Repeat("a", protocol.MaxCertUsageScopeLen+1)},
			wantUsage: "CertUsageServiceServer",
			wantScope: "invalid",
		},
		{
			name:      "empty scope",
			cu:        &protocol.CertUsage{Usage: protocol.CertUsageServiceServer},
			wantUsage: "CertUsageServiceServer",
			wantScope: "invalid",
		},
		{
			name:      "unknown usage",
			cu:        &protocol.CertUsage{Usage: protocol.CertUsageType(0x7F), Scope: "example"},
			wantUsage: "CertUsageType(127)",
			wantScope: "invalid",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op := &protocol.Operation{Opcode: protocol.OpMLDSA65Sign, SKI: protocol.SKI{1}, CertUsage: tt.cu}
			tags := spanTags(t, op)
			assert.Equal(t, tt.wantUsage, tags["operation.cert_usage"])
			assert.Equal(t, tt.wantScope, tags["operation.cert_usage_scope"])
			// Existing tags are unchanged.
			assert.Equal(t, protocol.OpMLDSA65Sign.String(), tags["operation.opcode"])
			assert.Contains(t, tags, "operation.ski")
			assert.Contains(t, tags, "operation.sni")
		})
	}
}

func TestSetOperationSpanTagsNoCertUsage(t *testing.T) {
	tags := spanTags(t, &protocol.Operation{Opcode: protocol.OpEd25519Sign})
	assert.NotContains(t, tags, "operation.cert_usage")
	assert.NotContains(t, tags, "operation.cert_usage_scope")
	assert.Equal(t, protocol.OpEd25519Sign.String(), tags["operation.opcode"])
}
