package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

func Test_initializeServerCertAndKey(t *testing.T) {
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "v1-xyz", r.Header.Get("X-Auth-User-Service-Key"))
		resp := initAPIResponse{
			Result: map[string]string{"certificate": "aa"},
		}
		resp.Success = true
		err := json.NewEncoder(w).Encode(resp)
		require.NoError(t, err)
	}))
	defer svr.Close()

	require.NoError(t, initConfig())
	config.ZoneID = "abc"
	config.InitEndpoint = svr.URL
	spew.Dump(config)
	config.fs = afero.NewMemMapFs()
	config.reader = strings.NewReader(`keyless.example.com
v1-xyz`)
	err := config.initializeServerCertAndKey()
	require.NoError(t, err)

	require.Equal(t, "v1-xyz", config.OriginCAKey)
	writtenCert, err := afero.ReadFile(config.fs, "server.pem")
	require.NoError(t, err)
	require.EqualValues(t, "aa", writtenCert)

}
