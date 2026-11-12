package protocol

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// tls13CV builds a TLS 1.3 CertificateVerify signing input with the given
// context string and a hash of hashLen bytes filled with hashByte.
func tls13CV(context string, hashLen int, hashByte byte) []byte {
	msg := bytes.Repeat([]byte{0x20}, 64)
	msg = append(msg, context...)
	msg = append(msg, 0x00)
	return append(msg, bytes.Repeat([]byte{hashByte}, hashLen)...)
}

func TestValidTLS13ServerCertificateVerify(t *testing.T) {
	const server = "TLS 1.3, server CertificateVerify"
	require.Equal(t, 98, tls13CertVerifyPrefixLen)

	mutate := func(msg []byte, f func([]byte)) []byte {
		f(msg)
		return msg
	}

	tests := []struct {
		name string
		msg  []byte
		want bool
	}{
		{"sha256 130 bytes", tls13CV(server, 32, 0xAB), true},
		{"sha384 146 bytes", tls13CV(server, 48, 0xAB), true},
		{"sha256 hash all 0x00", tls13CV(server, 32, 0x00), true},
		{"sha256 hash all 0xFF", tls13CV(server, 32, 0xFF), true},
		{"sha384 hash all 0x00", tls13CV(server, 48, 0x00), true},
		{"sha384 hash all 0xFF", tls13CV(server, 48, 0xFF), true},

		{"nil", nil, false},
		{"empty", []byte{}, false},
		{"len 97", tls13CV(server, 32, 0)[:97], false},
		{"len 98 prefix only", tls13CV(server, 0, 0), false},
		{"len 129", tls13CV(server, 31, 0), false},
		{"len 131", tls13CV(server, 33, 0), false},
		{"len 145", tls13CV(server, 47, 0), false},
		{"len 147", tls13CV(server, 49, 0), false},

		{"bad first padding byte", mutate(tls13CV(server, 32, 0), func(m []byte) { m[0] = 0x21 }), false},
		{"bad last padding byte", mutate(tls13CV(server, 32, 0), func(m []byte) { m[63] = 0x00 }), false},
		{"bad last padding byte sha384", mutate(tls13CV(server, 48, 0), func(m []byte) { m[63] = 0x21 }), false},
		{"client context sha256", tls13CV("TLS 1.3, client CertificateVerify", 32, 0), false},
		{"client context sha384", tls13CV("TLS 1.3, client CertificateVerify", 48, 0), false},
		{"context case differs", tls13CV("TLS 1.3, Server CertificateVerify", 32, 0), false},
		{"nonzero separator", mutate(tls13CV(server, 32, 0), func(m []byte) { m[97] = 0x01 }), false},
		{"separator is space", mutate(tls13CV(server, 48, 0), func(m []byte) { m[97] = 0x20 }), false},
		{
			// Separator dropped; total length restored by a longer hash so only
			// the framing (not the length) is wrong. The hash must not start
			// with 0x00, or it would itself read as the separator.
			"missing separator",
			append(append(bytes.Repeat([]byte{0x20}, 64), server...), bytes.Repeat([]byte{0xFF}, 33)...),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, ValidTLS13ServerCertificateVerify(tt.msg))
			// The reason must agree with ValidTLS13ServerCertificateVerify.
			reason := TLS13ServerCertificateVerifyRejectReason(tt.msg)
			require.Equal(t, reason == "", ValidTLS13ServerCertificateVerify(tt.msg), "reason %q", reason)
		})
	}

	// Lengths of the canonical valid messages.
	require.Len(t, tls13CV(server, 32, 0), 130)
	require.Len(t, tls13CV(server, 48, 0), 146)
}

func TestValidateCertUsage(t *testing.T) {
	cu := func(usage CertUsageType, scope string) *CertUsage {
		return &CertUsage{Usage: usage, Scope: scope}
	}
	valid := cu(CertUsageServiceServer, "example")

	tests := []struct {
		name    string
		op      Operation
		wantErr bool
	}{
		{"nil CertUsage", Operation{}, false},
		{"nil CertUsage with Extra and CertID", Operation{Extra: []byte("x"), CertID: "abc"}, false},
		{"valid", Operation{CertUsage: valid}, false},
		{"valid svc_a-1", Operation{CertUsage: cu(CertUsageServiceServer, "svc_a-1")}, false},
		{"valid 64 chars", Operation{CertUsage: cu(CertUsageServiceServer, strings.Repeat("a", 64))}, false},
		{"valid single char", Operation{CertUsage: cu(CertUsageServiceServer, "0")}, false},
		{"empty Extra slice is ok", Operation{CertUsage: valid, Extra: []byte{}}, false},

		{"CertUsage with Extra", Operation{CertUsage: valid, Extra: []byte("x")}, true},
		{"CertUsage with CertID", Operation{CertUsage: valid, CertID: "abc"}, true},
		{"CertUsage with Extra and CertID", Operation{CertUsage: valid, Extra: []byte("x"), CertID: "abc"}, true},
		{"unknown usage 0x00", Operation{CertUsage: cu(CertUsageType(0x00), "example")}, true},
		{"unknown usage 0x7F", Operation{CertUsage: cu(CertUsageType(0x7F), "example")}, true},
		{"empty scope", Operation{CertUsage: cu(CertUsageServiceServer, "")}, true},
		{"65 chars", Operation{CertUsage: cu(CertUsageServiceServer, strings.Repeat("a", 65))}, true},
		{"uppercase", Operation{CertUsage: cu(CertUsageServiceServer, "Example")}, true},
		{"space", Operation{CertUsage: cu(CertUsageServiceServer, "svc a")}, true},
		{"dot", Operation{CertUsage: cu(CertUsageServiceServer, "example.v2")}, true},
		{"slash", Operation{CertUsage: cu(CertUsageServiceServer, "example/v2")}, true},
		{"unicode", Operation{CertUsage: cu(CertUsageServiceServer, "exämple")}, true},
		{"nul byte", Operation{CertUsage: cu(CertUsageServiceServer, "example\x00")}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.op.ValidateCertUsage()
			if !tt.wantErr {
				require.NoError(t, err)
				return
			}
			// Must be the bare protocol Error value, not a wrapped error.
			require.Equal(t, ErrFormat, err)
			_, ok := err.(Error)
			require.True(t, ok)
		})
	}
}

func TestCertUsageValidate(t *testing.T) {
	require.NoError(t, (&CertUsage{Usage: CertUsageServiceServer, Scope: "example"}).Validate())
	require.Equal(t, ErrFormat, (&CertUsage{Usage: CertUsageType(0x02), Scope: "example"}).Validate())
	require.Equal(t, ErrFormat, (*CertUsage)(nil).Validate())
}

func TestTLS13ServerCertificateVerifyRejectReason(t *testing.T) {
	const server = "TLS 1.3, server CertificateVerify"
	bad := tls13CV(server, 48, 0xAB)
	bad[0] = 0x21
	require.Equal(t, "bad prefix", TLS13ServerCertificateVerifyRejectReason(bad))
	require.Equal(t, "bad prefix", TLS13ServerCertificateVerifyRejectReason(tls13CV("TLS 1.3, client CertificateVerify", 32, 0)))
	require.Equal(t, "length 0", TLS13ServerCertificateVerifyRejectReason(nil))
	require.Equal(t, "length 131", TLS13ServerCertificateVerifyRejectReason(tls13CV(server, 33, 0)))
	require.Empty(t, TLS13ServerCertificateVerifyRejectReason(tls13CV(server, 32, 0xAB)))
}

func TestCertUsageRejectReason(t *testing.T) {
	cases := map[string]struct {
		mutate func(*Operation)
		want   string
	}{
		"valid":         {func(*Operation) {}, ""},
		"extra":         {func(o *Operation) { o.Extra = []byte{0x00} }, "extra set"},
		"cert id":       {func(o *Operation) { o.CertID = "abc" }, "cert-id set"},
		"bad usage":     {func(o *Operation) { o.CertUsage.Usage = 0x02 }, "unknown usage 0x02"},
		"empty scope":   {func(o *Operation) { o.CertUsage.Scope = "" }, "scope length 0"},
		"long scope":    {func(o *Operation) { o.CertUsage.Scope = strings.Repeat("a", MaxCertUsageScopeLen+1) }, "scope length 65"},
		"uppercase":     {func(o *Operation) { o.CertUsage.Scope = "Secret" }, "scope has invalid character"},
		"max length":    {func(o *Operation) { o.CertUsage.Scope = strings.Repeat("a", MaxCertUsageScopeLen) }, ""},
		"no cert usage": {func(o *Operation) { o.CertUsage = nil }, ""},
		"no cert usage with extra and cert id": {func(o *Operation) {
			o.CertUsage, o.Extra, o.CertID = nil, []byte{0x00}, "abc"
		}, ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			op := Operation{CertUsage: &CertUsage{Usage: CertUsageServiceServer, Scope: "svc-a_1"}}
			tc.mutate(&op)
			got := op.CertUsageRejectReason()
			require.Equal(t, tc.want, got)
			// The reason must agree with ValidateCertUsage and never leak the scope.
			require.Equal(t, got == "", op.ValidateCertUsage() == nil)
			if op.CertUsage != nil && op.CertUsage.Scope != "" {
				require.NotContains(t, got, op.CertUsage.Scope)
			}
		})
	}
	require.Equal(t, "missing", (*CertUsage)(nil).rejectReason())
}
