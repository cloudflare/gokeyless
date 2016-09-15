package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/log"
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
	Port  string `json:"port,omitempty"`
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

	req.Header.Set("X-Auth-User-Service-Key", token.Token)

	log.Infof("making API call: %s", initEndpoint)
	resp, err := new(http.Client).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("certificate API returned an invalid response body for HTTP %d", resp.StatusCode)
	}

	apiResp := &initAPIResponse{}
	if err := json.Unmarshal(bodyBytes, apiResp); err != nil {
		log.Debugf("invalid JSON response: %s", bodyBytes)
		return nil, fmt.Errorf("certificate API returned HTTP %d", resp.StatusCode)
	}

	if !apiResp.Success {
		errs, _ := json.Marshal(apiResp.Errors)
		return nil, fmt.Errorf("certificate API call returned HTTP %d | %s", resp.StatusCode, errs)
	}

	if cert, ok := apiResp.Result["certificate"]; ok {
		return []byte(cert), nil
	}

	return nil, fmt.Errorf("no certificate in API response: %#v", apiResp)
}

func getToken() (*apiToken, error) {
	log.Infof("reading token from file %s", initToken)
	token := new(apiToken)
	f, err := os.Open(initToken)
	if err != nil {
		if f, err = os.Create(initToken); err != nil {
			return nil, err
		}
	}
	defer f.Close()

	if err := json.NewDecoder(f).Decode(token); err != nil {
		log.Errorf("couldn't read token from file %s: %v", initToken, err)
		token = tokenPrompt()
	}

	return token, nil
}

func initializeServerCertAndKey() {
	token, err := getToken()
	if err != nil {
		log.Fatal(err)
	}

	csr, key, err := generateCSR(token.Host)
	if err != nil {
		log.Fatal("failed to generate csr and key: ", err)
	}

	if err := ioutil.WriteFile(keyFile, key, 0600); err != nil {
		log.Fatal("failed to write to key file: ", err)
	}
	log.Infof("key is generated and saved to %s", keyFile)

	if err := ioutil.WriteFile(csrFile, csr, 0600); err != nil {
		log.Fatal("failed to write to csr file:", err)
	}
	log.Infof("csr is generated and saved to %s", csrFile)

	log.Info("contacting CloudFlare API for CSR signing")

	cert, err := initAPICall(token, string(csr))
	if err != nil {
		log.Fatal("initialization failed due to API error:", err)
	}

	if err := os.Remove(certFile); err != nil && !os.IsNotExist(err) {
		log.Fatal(err)
	}

	if err := ioutil.WriteFile(certFile, cert, 0644); err != nil {
		log.Fatal(err)
	}
	log.Infof("certificate saved to %s", certFile)

	return
}

// generateCSR generates a private key and a CSR for the given host. The
// generated key is persisted to file.
func generateCSR(host string) ([]byte, []byte, error) {
	csr, key, err := csr.ParseRequest(&csr.CertificateRequest{
		CN:    "Keyless Server Authentication Certificate",
		Hosts: []string{host},
		KeyRequest: &csr.BasicKeyRequest{
			A: "ecdsa",
			S: 384,
		},
	})

	return csr, key, err
}

// tokenPrompt populates the Host and Token fields of a new *apiToken.
func tokenPrompt() *apiToken {
	token := &apiToken{}

	fmt.Print("Keyserver Hostname: ")
	fmt.Scanln(&token.Host)
	fmt.Print("Certificates API Key: ")
	fmt.Scanln(&token.Token)

	return token
}

func manualActivation() {
	var host string
	fmt.Print("Keyserver Hostname: ")
	fmt.Scanln(&host)
	csr, key, err := generateCSR(host)
	if err != nil {
		log.Fatal("failed to generate csr and key: ", err)
	}

	if err := ioutil.WriteFile(keyFile, key, 0600); err != nil {
		log.Fatal("failed to write to key file:", err)
	}
	log.Infof("key is generated and saved to %s", keyFile)

	if err := ioutil.WriteFile(csrFile, csr, 0600); err != nil {
		log.Fatal("failed to write to csr file:", err)
	}
	log.Infof("csr is generated and saved to %s", csrFile)
}
