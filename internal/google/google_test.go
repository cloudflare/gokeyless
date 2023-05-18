package google

import (
	"context"
	"crypto"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestIsKMSResource(t *testing.T) {
	require.True(t, IsKMSResource("projects/abc/locations/us-west1/keyRings/xyz/cryptoKeys/example-key/cryptoKeyVersions/3"))
	require.False(t, IsKMSResource("projects/abc/locations/us-west1/keyRings/xyz/cryptoKeys/example-key/cryptoKeyVersions"))

}

type mockKMS struct{}

func (k mockKMS) AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error) {
	digest := req.Digest.GetSha256()
	return &kmspb.AsymmetricSignResponse{
		Signature:            digest,
		VerifiedDigestCrc32C: true,
		SignatureCrc32C:      wrapperspb.Int64(int64(crc32c(digest))),
	}, nil
}
func (k mockKMS) GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...gax.CallOption) (*kmspb.PublicKey, error) {
	return &kmspb.PublicKey{}, nil
}
func TestSmoke(t *testing.T) {
	require := require.New(t)
	pub := []byte("key")
	k := KMSSigner{
		pub:     pub,
		keyType: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
		client:  &mockKMS{},
	}
	require.Equal(k.Public(), pub)

	sig, err := k.Sign(nil, []byte("digest"), crypto.SHA256)
	require.NoError(err)
	require.Equal(sig, []byte("digest"))

}
