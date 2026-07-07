package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	cloudflare "github.com/cloudflare/cloudflare-go"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

// originCATestResponse mirrors the JSON envelope the Origin CA certificates
// endpoint returns for a successful keyless-certificate request.
type originCATestResponse struct {
	cloudflare.Response
	Result struct {
		Certificate string `json:"certificate"`
	} `json:"result"`
}

func newCertServer(t *testing.T, assert func(r *http.Request)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/certificates", r.URL.Path)
		assert(r)

		resp := originCATestResponse{}
		resp.Success = true
		resp.Result.Certificate = "aa"
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	}))
}

func Test_initializeServerCertAndKey_ServiceKey(t *testing.T) {
	svr := newCertServer(t, func(r *http.Request) {
		require.Equal(t, "v1-xyz", r.Header.Get("X-Auth-User-Service-Key"))
		require.Empty(t, r.Header.Get("Authorization"))
	})
	defer svr.Close()

	require.NoError(t, initConfig())
	config.APIToken = ""
	config.OriginCAKey = "v1-xyz"
	config.Hostname = "keyless.example.com"
	config.ZoneID = "abc"
	config.InitEndpoint = svr.URL
	config.fs = afero.NewMemMapFs()
	config.reader = strings.NewReader("")

	require.NoError(t, config.initializeServerCertAndKey())

	writtenCert, err := afero.ReadFile(config.fs, "server.pem")
	require.NoError(t, err)
	require.EqualValues(t, "aa", writtenCert)
}

func Test_initializeServerCertAndKey_APIToken(t *testing.T) {
	svr := newCertServer(t, func(r *http.Request) {
		require.Equal(t, "Bearer tok-123", r.Header.Get("Authorization"))
		require.Empty(t, r.Header.Get("X-Auth-User-Service-Key"))
	})
	defer svr.Close()

	require.NoError(t, initConfig())
	config.APIToken = "tok-123"
	config.OriginCAKey = ""
	config.Hostname = "keyless.example.com"
	config.ZoneID = "abc"
	config.InitEndpoint = svr.URL
	config.fs = afero.NewMemMapFs()
	config.reader = strings.NewReader("")

	require.NoError(t, config.initializeServerCertAndKey())

	writtenCert, err := afero.ReadFile(config.fs, "server.pem")
	require.NoError(t, err)
	require.EqualValues(t, "aa", writtenCert)
}

func Test_initAPICall_sendsZoneIDAndRequestType(t *testing.T) {
	svr := newCertServer(t, func(r *http.Request) {
		var body initAPIRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, "keyless-certificate", body.Rqtype)
		require.Equal(t, "zone-1", body.ZoneID)
		require.Equal(t, []string{"keyless.example.com"}, body.Hostnames)
		require.Equal(t, "the-csr", body.CSR)
	})
	defer svr.Close()

	require.NoError(t, initConfig())
	config.APIToken = "tok-123"
	config.OriginCAKey = ""
	config.InitEndpoint = svr.URL

	cert, err := config.initAPICall("keyless.example.com", "zone-1", "the-csr")
	require.NoError(t, err)
	require.EqualValues(t, "aa", cert)
}

// Test_initAPICall_prefersAPITokenOverServiceKey verifies that when both an
// API token and the legacy Origin CA Service Key are configured, the request
// is authenticated with the token (Bearer) and the service-key header is not
// sent. This locks in the "prefer token, fall back to key" precedence in
// newCFClient.
func Test_initAPICall_prefersAPITokenOverServiceKey(t *testing.T) {
	svr := newCertServer(t, func(r *http.Request) {
		require.Equal(t, "Bearer tok-123", r.Header.Get("Authorization"))
		require.Empty(t, r.Header.Get("X-Auth-User-Service-Key"))
	})
	defer svr.Close()

	require.NoError(t, initConfig())
	config.APIToken = "tok-123"
	config.OriginCAKey = "v1-xyz" // both set; the token must win
	config.InitEndpoint = svr.URL

	cert, err := config.initAPICall("keyless.example.com", "zone-1", "the-csr")
	require.NoError(t, err)
	require.EqualValues(t, "aa", cert)
}

// Test_initAPICall_noCredentials verifies that initAPICall fails clearly when
// neither credential is configured (newCFClient returns an error before any
// network call is attempted).
func Test_initAPICall_noCredentials(t *testing.T) {
	require.NoError(t, initConfig())
	config.APIToken = ""
	config.OriginCAKey = ""

	_, err := config.initAPICall("keyless.example.com", "zone-1", "the-csr")
	require.Error(t, err)
	require.Contains(t, err.Error(), "no Cloudflare credentials configured")
}

// Test_initAPICall_emptyCertificate verifies the guard that treats a
// successful response with a blank certificate field as an error.
func Test_initAPICall_emptyCertificate(t *testing.T) {
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/certificates", r.URL.Path)
		resp := originCATestResponse{}
		resp.Success = true
		resp.Result.Certificate = ""
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	}))
	defer svr.Close()

	require.NoError(t, initConfig())
	config.APIToken = "tok-123"
	config.OriginCAKey = ""
	config.InitEndpoint = svr.URL

	_, err := config.initAPICall("keyless.example.com", "zone-1", "the-csr")
	require.Error(t, err)
	require.Contains(t, err.Error(), "no certificate in API response")
}

// Test_initializeServerCertAndKey_apiErrorDoesNotWriteCert mirrors the live
// failure mode (e.g. Cloudflare error 1301 when the keyless hostname is not
// registered): the API call fails, no server certificate is written, but the
// locally generated key/CSR are still persisted.
func Test_initializeServerCertAndKey_apiErrorDoesNotWriteCert(t *testing.T) {
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/certificates", r.URL.Path)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":1301,"message":"cannot find keyless server hostname in the records"}],"result":null}`))
	}))
	defer svr.Close()

	require.NoError(t, initConfig())
	config.APIToken = "tok-123"
	config.OriginCAKey = ""
	config.Hostname = "keyless.example.com"
	config.ZoneID = "abc"
	config.InitEndpoint = svr.URL
	config.fs = afero.NewMemMapFs()
	config.reader = strings.NewReader("")

	err := config.initializeServerCertAndKey()
	require.Error(t, err)
	require.Contains(t, err.Error(), "initialization failed due to API error")

	// The signed certificate must not be written when the API call fails.
	certExists, err := afero.Exists(config.fs, config.CertFile)
	require.NoError(t, err)
	require.False(t, certExists, "server certificate should not be written on API error")

	// The key and CSR are generated before the API call, so they should exist.
	keyExists, err := afero.Exists(config.fs, config.KeyFile)
	require.NoError(t, err)
	require.True(t, keyExists)
}

// Test_interactivePrompt_populatesAPIToken verifies the interactive prompt
// stores the entered credential in APIToken (the preferred field) and trims
// surrounding whitespace.
func Test_interactivePrompt_populatesAPIToken(t *testing.T) {
	require.NoError(t, initConfig())
	config.Hostname = "keyless.example.com"
	config.ZoneID = "zone-1"
	config.APIToken = ""
	config.OriginCAKey = ""
	config.reader = strings.NewReader("  tok-xyz  \n")

	require.NoError(t, config.interactivePrompt())
	require.Equal(t, "tok-xyz", config.APIToken)
	require.Empty(t, config.OriginCAKey)
}

func Test_needInteractivePrompt(t *testing.T) {
	base := Config{Hostname: "h", ZoneID: "z"}

	withToken := base
	withToken.APIToken = "tok"
	require.False(t, withToken.needInteractivePrompt())

	withServiceKey := base
	withServiceKey.OriginCAKey = "key"
	require.False(t, withServiceKey.needInteractivePrompt())

	noCreds := base
	require.True(t, noCreds.needInteractivePrompt())
}

func Test_deriveBaseURL(t *testing.T) {
	require.Equal(t, "https://api.cloudflare.com/client/v4",
		deriveBaseURL("https://api.cloudflare.com/client/v4/certificates/"))
	require.Equal(t, "https://api.cloudflare.com/client/v4",
		deriveBaseURL("https://api.cloudflare.com/client/v4/certificates"))
	require.Equal(t, "http://127.0.0.1:8080", deriveBaseURL("http://127.0.0.1:8080"))
	require.Equal(t, "", deriveBaseURL(""))
}
