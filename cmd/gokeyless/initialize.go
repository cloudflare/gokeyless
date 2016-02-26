package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"

	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/gokeyless/server"
)

type v4apiError struct {
	Code    json.Number `json:"code,omitempty"`
	Message string      `json:"message,omitempty"`
}

type initAPIRequest struct {
	Rqtype    string   `json:"request_type,omitempty"`
	Hostnames []string `json:"hostnames,omitempty"`
	CSR       string   `json:"csr,omitempty"`
	//Days      int      `json:"requested_validity,omitempty"`
}

func newRequestBody(hostname, csr string) (io.Reader, error) {
	apiReq := initAPIRequest{
		Rqtype:    "keyless-certificate",
		Hostnames: []string{hostname},
		CSR:       csr,
	}
	body := new(bytes.Buffer)
	err := json.NewEncoder(body).Encode(apiReq)
	return body, err
}

type initAPIResponse struct {
	Success  bool              `json:"success,omitempty"`
	Messages []string          `json:"messages,omitempty"`
	Errors   []v4apiError      `json:"errors,omitempty"`
	Result   map[string]string `json:"result,omitempty"`
}

type apiToken struct {
	Token string `json:"token"`
	Host  string `json:"host"`
	Port  string `json:"port"`
}

func initAPICall(token *apiToken, csr string) ([]byte, error) {
	body, err := newRequestBody(token.Host, csr)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", initEndpoint, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-Auth-Key", token.Token)

	resp, err := new(http.Client).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	apiResp := new(initAPIResponse)
	if err := json.NewDecoder(resp.Body).Decode(apiResp); err != nil {
		return nil, err
	}
	if !apiResp.Success {
		errs, _ := json.Marshal(apiResp.Errors)
		return nil, fmt.Errorf("api call failed: %s", errs)
	}

	if cert, ok := apiResp.Result["certificate"]; ok {
		return []byte(cert), nil
	}
	return nil, fmt.Errorf("no certificate in api response: %#v", apiResp)
}

func initializeServer() *server.Server {
	b, err := ioutil.ReadFile(initToken)
	if err != nil {
		log.Fatalf("Couldn't read JSON token %s: %v", initToken, err)
	}

	token := new(apiToken)
	if err := json.Unmarshal(b, token); err != nil {
		log.Fatalf("Couldn't unmarshal JSON token: %v", err)
	}
	csr, key, err := csr.ParseRequest(&csr.CertificateRequest{
		CN:    "Keyless Server Authentication Certificate",
		Hosts: []string{token.Host},
		KeyRequest: &csr.BasicKeyRequest{
			A: "ecdsa",
			S: 384,
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	if err := os.Remove(keyFile); err != nil && !os.IsNotExist(err) {
		log.Fatal(err)
	}

	if err := ioutil.WriteFile(keyFile, key, 0400); err == nil {
		log.Infof("Key generated and saved to %s\n", keyFile)
	}

	log.Info("Server entering initialization state")
	s, err := server.NewServerFromFile(initCertFile, initKeyFile, caFile,
		net.JoinHostPort("", port), net.JoinHostPort("", metricsPort))
	if err != nil {
		log.Fatal(err)
	}
	s.ActivationToken = []byte(token.Token)
	go func() {
		log.Fatal(s.ListenAndServe())
	}()

	cert, err := initAPICall(token, string(csr))
	if err != nil {
		log.Fatal(err)
	}

	if err := os.Remove(certFile); err != nil && !os.IsNotExist(err) {
		log.Fatal(err)
	}

	if err := ioutil.WriteFile(certFile, cert, 0644); err != nil {
		log.Fatal(err)
	}
	log.Infof("Cert saved to %s\n", certFile)

	// Remove server from activation state and initialize issued certificate.
	s.ActivationToken = s.ActivationToken[:0]
	tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatal(err)
	}

	s.Config.Certificates = []tls.Certificate{tlsCert}
	return s
}
