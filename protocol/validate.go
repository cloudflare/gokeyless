package protocol

import (
	"bytes"
	"fmt"
)

// TLS 1.3 server CertificateVerify signing input framing (RFC 8446, Section 4.4.3).
const (
	tls13CertVerifyPadLen        = 64
	tls13CertVerifyPadByte       = 0x20
	tls13ServerCertVerifyContext = "TLS 1.3, server CertificateVerify"
	tls13CertVerifySeparator     = 0x00
	// tls13CertVerifyPrefixLen is 64 + 33 + 1 = 98 bytes.
	tls13CertVerifyPrefixLen = tls13CertVerifyPadLen + len(tls13ServerCertVerifyContext) + 1
)

// ValidTLS13ServerCertificateVerify reports whether msg is a TLS 1.3 server
// CertificateVerify signing input with a SHA-256 or SHA-384 transcript hash,
// i.e. exactly 130 or 146 bytes. This keeps ML-DSA keys from signing arbitrary messages.
func ValidTLS13ServerCertificateVerify(msg []byte) bool {
	return TLS13ServerCertificateVerifyRejectReason(msg) == ""
}

// TLS13ServerCertificateVerifyRejectReason returns why msg fails
// ValidTLS13ServerCertificateVerify, for logging, or "" if it is valid.
func TLS13ServerCertificateVerifyRejectReason(msg []byte) string {
	switch len(msg) - tls13CertVerifyPrefixLen {
	case 32, 48: // SHA-256, SHA-384
	default:
		return fmt.Sprintf("length %d", len(msg))
	}
	for _, b := range msg[:tls13CertVerifyPadLen] {
		if b != tls13CertVerifyPadByte {
			return "bad prefix"
		}
	}
	ctx := msg[tls13CertVerifyPadLen : tls13CertVerifyPrefixLen-1]
	if !bytes.Equal(ctx, []byte(tls13ServerCertVerifyContext)) ||
		msg[tls13CertVerifyPrefixLen-1] != tls13CertVerifySeparator {
		return "bad prefix"
	}
	return ""
}

// MaxCertUsageScopeLen is the maximum length in bytes of CertUsage.Scope.
const MaxCertUsageScopeLen = 64

// Validate requires Usage to be CertUsageServiceServer and Scope to be 1 to
// MaxCertUsageScopeLen bytes of [a-z0-9_-]. It returns ErrFormat (unwrapped) on failure.
func (c *CertUsage) Validate() error {
	if c.rejectReason() != "" {
		return ErrFormat
	}
	return nil
}

// rejectReason returns why c fails Validate, or "" if it is valid.
// It never includes the scope itself.
func (c *CertUsage) rejectReason() string {
	if c == nil {
		return "missing"
	}
	switch c.Usage {
	case CertUsageServiceServer:
	default:
		return fmt.Sprintf("unknown usage 0x%02x", byte(c.Usage))
	}
	if len(c.Scope) == 0 || len(c.Scope) > MaxCertUsageScopeLen {
		return fmt.Sprintf("scope length %d", len(c.Scope))
	}
	for i := 0; i < len(c.Scope); i++ {
		b := c.Scope[i]
		if (b < 'a' || b > 'z') && (b < '0' || b > '9') && b != '_' && b != '-' {
			return "scope has invalid character"
		}
	}
	return ""
}

// ValidateCertUsage returns nil if o has no CertUsage. Otherwise Extra and
// CertID must be empty and CertUsage must pass Validate; it returns ErrFormat
// (unwrapped) on failure.
func (o *Operation) ValidateCertUsage() error {
	if o.CertUsageRejectReason() != "" {
		return ErrFormat
	}
	return nil
}

// CertUsageRejectReason returns why o fails ValidateCertUsage, for logging, or
// "" if it passes. It never includes the scope itself.
func (o *Operation) CertUsageRejectReason() string {
	switch {
	case o.CertUsage == nil:
		return ""
	case len(o.Extra) != 0:
		return "extra set"
	case o.CertID != "":
		return "cert-id set"
	}
	return o.CertUsage.rejectReason()
}
