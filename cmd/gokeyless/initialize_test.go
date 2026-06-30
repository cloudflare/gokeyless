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
