package azure

import (
	"context"
	"crypto"
	"testing"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/keyvault/keyvault"
	"github.com/stretchr/testify/require"
)

func Test_parseKeyURL(t *testing.T) {

	tests := []struct {
		name           string
		url            string
		wantBaseURL    string
		wantKeyName    string
		wantKeyVersion string
		wantErr        bool
	}{
		{
			url:            "https://vault-name.vault.azure.net/keys/key-name/abc",
			wantBaseURL:    "https://vault-name.vault.azure.net",
			wantKeyName:    "key-name",
			wantKeyVersion: "abc",
		},
		{
			url:            "https://vault-name.managedhsm.azure.net/keys/key-name/abc",
			wantBaseURL:    "https://vault-name.managedhsm.azure.net",
			wantKeyName:    "key-name",
			wantKeyVersion: "abc",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotBaseURL, gotKeyName, gotKeyVersion, err := parseKeyURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseKeyURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			require.Equal(t, gotBaseURL, tt.wantBaseURL)
			require.Equal(t, gotKeyName, tt.wantKeyName)
			require.Equal(t, gotKeyVersion, tt.wantKeyVersion)
		})
	}
}

type mockVault struct{}

func (m mockVault) Sign(_ context.Context, vaultBaseURL string, keyName string, keyVersion string, parameters keyvault.KeySignParameters) (result keyvault.KeyOperationResult, err error) {
	return keyvault.KeyOperationResult{Result: parameters.Value}, nil
}
func (m mockVault) GetKey(_ context.Context, vaultBaseURL string, keyName string, keyVersion string) (result keyvault.KeyBundle, err error) {
	return keyvault.KeyBundle{}, nil
}
func TestSmoke(t *testing.T) {
	require := require.New(t)
	pub := []byte("key")
	k := KeyVaultSigner{
		pub:     pub,
		keyType: keyvault.RSA,
		client:  &mockVault{},
	}
	require.Equal(k.Public(), pub)
	alg, err := k.determineSigAlg(crypto.SHA384)
	require.Equal(alg, keyvault.RS384)
	require.NoError(err)

	sig, err := k.Sign(nil, []byte("digest"), crypto.SHA384)
	require.Equal(sig, []byte("digest"))
	require.NoError(err)

}
