package azure

import (
	"context"
	"crypto"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/keyvault/keyvault"
	kvauth "github.com/Azure/azure-sdk-for-go/services/keyvault/auth"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/cloudflare/cfssl/log"
	jose "gopkg.in/square/go-jose.v2"
)

type keyVault interface {
	Sign(ctx context.Context, vaultBaseURL string, keyName string, keyVersion string, parameters keyvault.KeySignParameters) (result keyvault.KeyOperationResult, err error)
	GetKey(ctx context.Context, vaultBaseURL string, keyName string, keyVersion string) (result keyvault.KeyBundle, err error)
}

// KeyVaultSigner is foo https://github.com/Azure-Samples/azure-sdk-for-go-samples/tree/master/keyvault/examples
type KeyVaultSigner struct {
	client                       keyVault
	baseURL, keyName, keyVersion string

	// If the key changes, so does the keyVersion,
	// so we can cache the public key info forever for subsequent calls to `Public()` and `Sign()` to use.
	pub     crypto.PublicKey
	keyType keyvault.JSONWebKeyType
}

// must conform to the interface
var _ crypto.Signer = KeyVaultSigner{}

// New creates a client that implements `crypto.Signer` backed by Azure Key Vault or Azure Managed HSM at the given uri
// The URL should be contain the key version (i.e. `https://vault-name.vault.azure.net/keys/key-name/abc`)
// Required roles are `/keys/read/action` and `/keys/sign/action`, the minimum built in Role that fuffils these is `Crypto User`
// RBAC reference: https://docs.microsoft.com/en-us/azure/key-vault/managed-hsm/built-in-roles#permitted-operations
// This means the role must be
func New(url string) (*KeyVaultSigner, error) {

	baseURL, keyName, keyVersion, err := parseKeyURL(url)
	if err != nil {
		return nil, err
	}

	client, err := makeClientWithAuth(baseURL)
	if err != nil {
		return nil, err
	}

	s := KeyVaultSigner{
		client:     client,
		baseURL:    baseURL,
		keyName:    keyName,
		keyVersion: keyVersion,
	}

	// Fetch public key (and validate that it's supported)
	err = s.getPublicKey(context.Background())
	if err != nil {
		return nil, err
	}

	return &s, nil
}

// Public returns the Public Key
func (k KeyVaultSigner) Public() crypto.PublicKey {
	return k.pub
}

// Sign makes an API call to sign the provided bytes, mapping the hash in `crypto.SignerOps` to a JWK Signature Algorithm
func (k KeyVaultSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {

	// base64url required as per https://docs.microsoft.com/en-us/azure/key-vault/general/about-keys-secrets-certificates#data-types
	payload := base64.RawURLEncoding.EncodeToString(digest)

	algo, err := k.determineSigAlg(opts)
	if err != nil {
		return nil, err
	}

	signed, err := k.client.Sign(context.Background(), k.baseURL, k.keyName, k.keyVersion, keyvault.KeySignParameters{Algorithm: algo, Value: &payload})
	if err != nil {
		return nil, fmt.Errorf("azure: failed to sign: %w", err)
	}

	res, err := base64.RawURLEncoding.DecodeString(*signed.Result)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 recode result: `%s` %w", *signed.Result, err)
	}

	log.Debugf("azure: signed %d bytes with %s for %s key %s", len(digest), algo, k.keyType, k.keyName)

	if k.keyType == keyvault.RSA {
		return res, nil
	}
	// EC needs an additional transform
	return convert1363ToAsn1(res)
}

//	map the signature algirthm to the relevant JWK one
//
// see https://tools.ietf.org/html/rfc7518#section-3.1
func (k KeyVaultSigner) determineSigAlg(opts crypto.SignerOpts) (algo keyvault.JSONWebKeySignatureAlgorithm, err error) {
	switch {
	case k.keyType == keyvault.EC && opts == crypto.SHA256: // for OpECDSASignSHA256
		algo = keyvault.ES256
	case k.keyType == keyvault.EC && opts == crypto.SHA384: // for OpECDSASignSHA384
		algo = keyvault.ES384
	case k.keyType == keyvault.EC && opts == crypto.SHA512: // for OpECDSASignSHA512
		algo = keyvault.ES512
	case k.keyType == keyvault.RSA && opts == crypto.SHA256: // for OpRSASignSHA256
		algo = keyvault.RS256
	case k.keyType == keyvault.RSA && opts == crypto.SHA384: // for OpRSASignSHA384
		algo = keyvault.RS384
	case k.keyType == keyvault.RSA && opts == crypto.SHA512: // for OpRSASignSHA512
		algo = keyvault.RS512
	default:
		return keyvault.RSNULL, fmt.Errorf("azure: unsupported opt: %s for key %s", opts.HashFunc().String(), k.keyType)
	}
	return
}

// getPublicKey does the following:
// 1. fetch the specified version of the key
// 2. Ensure that the key type supports a signing operation that is also supported by keyless.
// 3. marshals the JWK into json, so that it can be unmarshalled into jose's JWK format
// 4. extract the public key from the JWK (crypto.Signer's `Public()` must be implemented so keyless can calculate the SKI)
//
// note: other similar codebases directly massage the public key out of the keyvault.KeyBundle
// see:
// https://github.com/ThalesGroup/sshizzle/blob/master/internal/azure/keyvaultsigner.go#L40
// https://github.com/vdh-oim/COVIDWISE/blob/master/server/internal/signing/azure_keyvault.go#L165
// using `jose` instead hides the complexity
func (k *KeyVaultSigner) getPublicKey(ctx context.Context) error {
	keyBundle, err := k.client.GetKey(ctx, k.baseURL, k.keyName, k.keyVersion)
	if err != nil {
		return fmt.Errorf("azure: failed to fetch key bundle: %w", err)
	}

	// https://docs.microsoft.com/en-us/azure/key-vault/keys/about-keys#key-types-and-protection-methods
	switch keyBundle.Key.Kty {
	case keyvault.EC:
	case keyvault.RSA:
	// need to remove `EC-` prefix to avoid `failed to unmarshal jwk: square/go-jose: unknown json web key type 'EC-HSM'``
	case keyvault.ECHSM:
		keyBundle.Key.Kty = keyvault.EC
	case keyvault.RSAHSM:
		keyBundle.Key.Kty = keyvault.RSA
	default:
		return fmt.Errorf("azure: unsupported key type: %s", keyBundle.Key.Kty)
	}

	jwkJSON, err := json.Marshal(keyBundle.Key)
	if err != nil {
		return fmt.Errorf("azure: failed to marshal key bundle: %w", err)
	}

	jwk := jose.JSONWebKey{}
	err = jwk.UnmarshalJSON(jwkJSON)
	if err != nil {
		return fmt.Errorf("azure: failed to unmarshal jwk: %w", err)
	}

	// persist for future operations
	k.pub = jwk.Key
	k.keyType = keyBundle.Key.Kty

	return nil
}

// IsKeyVaultURI determines if a url is likely an Azure Key Vault URL
// base URLs defined at https://docs.microsoft.com/en-us/azure/key-vault/general/about-keys-secrets-certificates
func IsKeyVaultURI(url string) bool {
	urls := []string{
		"managedhsm.azure.net",
		azure.ChinaCloud.KeyVaultDNSSuffix,
		azure.GermanCloud.KeyVaultDNSSuffix,
		azure.PublicCloud.KeyVaultDNSSuffix,
		azure.USGovernmentCloud.KeyVaultDNSSuffix,
	}
	for _, k := range urls {
		if strings.Contains(url, fmt.Sprintf("%s/keys/", k)) {
			return true
		}
	}
	return false
}

func parseKeyURL(url string) (baseURL, keyName, keyVersion string, err error) {
	if !(IsKeyVaultURI(url)) {
		err = fmt.Errorf("azure: invalid url: %s", url)
		return
	}
	parts := strings.Split(url, "/")
	if len(parts) != 6 {
		err = fmt.Errorf("azure: invalid url: %s", url)
		return
	}
	baseURL = strings.Join(parts[:3], "/")
	keyName = parts[4]
	keyVersion = parts[5]
	return
}

// makeClientWithAuth tries to auth based on environment variables.
// See https://pkg.go.dev/github.com/Azure/go-autorest/autorest/azure/auth for instructions
// https://docs.microsoft.com/en-us/azure/developer/go/azure-sdk-authorization#use-file-based-authentication
//
// we first try to load auth via `NewAuthorizerFromFile`, and then if that fails, `NewAuthorizerFromEnvironment`
func makeClientWithAuth(baseURL string) (*keyvault.BaseClient, error) {

	var authorizer autorest.Authorizer
	var err error

	// `Environment` (https://pkg.go.dev/github.com/Azure/go-autorest/autorest/azure#pkg-variables) does not have the endpoint for managed HSM,
	// which means that the initial auth will fail with the error `Found token with aud=https://vault.azure.net, but expected aud=https://managedhsm.azure.net`
	//
	// Managed HSM is currently only supported in Azure Public Cloud so we don't need to switch on the region.
	// (https://docs.microsoft.com/en-us/azure/key-vault/general/about-keys-secrets-certificates)

	if strings.Contains(baseURL, "managedhsm.azure.net") {
		authorizer, err = auth.NewAuthorizerFromFileWithResource("https://managedhsm.azure.net")
		if err != nil {
			authorizer, err = auth.NewAuthorizerFromEnvironmentWithResource("https://managedhsm.azure.net")
		}
	} else {
		authorizer, err = kvauth.NewAuthorizerFromFile()
		if err != nil {
			authorizer, err = kvauth.NewAuthorizerFromEnvironment()

		}
	}
	if err != nil {
		return nil, fmt.Errorf("azure: failed to auth: %w", err)
	}

	basicClient := keyvault.New()
	basicClient.Authorizer = authorizer
	return &basicClient, nil
}

// necessary to convert from IEEE 1363 to ASN.1,
// copied from https://github.com/google/exposure-notifications-server/blob/main/pkg/keys/azure_keyvault.go#L412-L414
func convert1363ToAsn1(b []byte) ([]byte, error) {
	rs := struct {
		R, S *big.Int
	}{
		R: new(big.Int).SetBytes(b[:len(b)/2]),
		S: new(big.Int).SetBytes(b[len(b)/2:]),
	}

	return asn1.Marshal(rs)
}
