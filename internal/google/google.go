package google

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"hash/crc32"
	"io"
	"strings"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/cloudflare/cfssl/log"
	"github.com/googleapis/gax-go/v2"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type kmsClient interface {
	AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error)
	GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...gax.CallOption) (*kmspb.PublicKey, error)
}

// KMSSigner is a crypto.Signer for Google Cloud KMS
type KMSSigner struct {
	client kmsClient
	name   string

	// If the key changes, so does the version number in the `name`,
	// so we can cache the public key info forever for subsequent calls to `Public()` and `Sign()` to use.
	pub     crypto.PublicKey
	keyType kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
}

// must conform to the interface
var _ crypto.Signer = KMSSigner{}

// New creates a new signer with the given KMS key resource name
func New(name string) (*KMSSigner, error) {
	ctx := context.Background()
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("google: failed to create kms client: %w", err)
	}
	k := KMSSigner{
		client: client,
		name:   name}
	err = k.getPublicKey(ctx)
	if err != nil {
		return nil, err
	}
	return &k, nil
}

// Public returns the Public Key
func (k KMSSigner) Public() crypto.PublicKey {
	return k.pub
}

// Sign makes an API call to sign the provided bytes, mapping the hash in `crypto.SignerOps` to a JWK Signature Algorithm
func (k KMSSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	var payload kmspb.Digest
	switch opts {
	case crypto.SHA256: // for OpECDSASignSHA256 and OpRSASignSHA256
		payload.Digest = &kmspb.Digest_Sha256{
			Sha256: digest,
		}
	case crypto.SHA384: // for OpECDSASignSHA384 and OpRSASignSHA384
		payload.Digest = &kmspb.Digest_Sha384{
			Sha384: digest,
		}
	case crypto.SHA512: // for OpECDSASignSHA512 and OpRSASignSHA512
		payload.Digest = &kmspb.Digest_Sha512{
			Sha512: digest,
		}
	default:
		return nil, fmt.Errorf("google: unsupported opt: %s for key %s", opts.HashFunc().String(), k.name)
	}

	req := &kmspb.AsymmetricSignRequest{
		Name:         k.name,
		Digest:       &payload,
		DigestCrc32C: wrapperspb.Int64(int64(crc32c(digest))),
	}

	// Call the API.
	result, err := k.client.AsymmetricSign(context.Background(), req)
	if err != nil {
		return nil, fmt.Errorf("google: failed to sign digest: %w", err)
	}

	// https://cloud.google.com/kms/docs/data-integrity-guidelines
	if result.VerifiedDigestCrc32C == false {
		return nil, fmt.Errorf("google: digest CRC32 not verified")
	}
	if int64(crc32c(result.Signature)) != result.SignatureCrc32C.Value {
		return nil, fmt.Errorf("google: signature crc32 incorrect")
	}

	log.Debugf("google: signed %d bytes with %s for %s key %s", len(digest), opts.HashFunc().String(), k.keyType, k.name)

	return result.Signature, nil

}

// IsKMSResource attempts to identify if a name is a KMS `Key version`
// format specified at https://cloud.google.com/kms/docs/resource-hierarchy#retrieve_resource_id
func IsKMSResource(name string) bool {
	return strings.Contains(name, "/keyRings/") && strings.Contains(name, "/cryptoKeyVersions/") && len(strings.Split(name, "/")) == 10
}
func (k *KMSSigner) getPublicKey(ctx context.Context) error {
	response, err := k.client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: k.name})
	if err != nil {
		return fmt.Errorf("google: failed to get public key: %w", err)
	}

	block, _ := pem.Decode([]byte(response.Pem))
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("google: failed to parse public key: %w", err)
	}

	k.pub = publicKey
	k.keyType = response.Algorithm
	switch k.keyType {
	case kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512,

		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512,

		kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
		kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384:
	default:
		return fmt.Errorf("google: key algorithm %s not supported, must be of type 'sign'", k.keyType)
	}
	return nil
}

// from https://cloud.google.com/kms/docs/samples/kms-sign-asymmetric#kms_sign_asymmetric-go
func crc32c(data []byte) uint32 {
	t := crc32.MakeTable(crc32.Castagnoli)
	return crc32.Checksum(data, t)
}
