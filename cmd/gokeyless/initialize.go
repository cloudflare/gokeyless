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
	ZoneID    string   `json:"zone_id,omitemtpy"`
	CSR       string   `json:"csr,omitempty"`
	//Days      int      `json:"requested_validity,omitempty"`
}

func newRequestBody(hostname, zoneID, csr string) (io.Reader, error) {
	apiReq := initAPIRequest{
		Rqtype:    "keyless-certificate",
		Hostnames: []string{hostname},
		ZoneID:    zoneID,
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

func initAPICall(token, hostname, zoneID, csr string) ([]byte, error) {
	body, err := newRequestBody(hostname, zoneID, csr)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", initEndpoint, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-Auth-User-Service-Key", token)

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

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("certificate API returns non-200 response, HTTP code: %d, Response: %s", resp.StatusCode, string(bodyBytes))
	}
	apiResp := &initAPIResponse{}
	err = json.Unmarshal(bodyBytes, apiResp)
	if err != nil {
		return nil, fmt.Errorf("unable to parse certificate API response,  HTTP Response: %s", string(bodyBytes))
	}

	if !apiResp.Success {
		return nil, fmt.Errorf("certificate API call returnes errors: %s", string(bodyBytes))
	}

	if cert, ok := apiResp.Result["certificate"]; ok {
		return []byte(cert), nil
	}

	return nil, fmt.Errorf("no certificate in API response: %#v", apiResp)
}

// tokenFromPrompt populates the Host and Token fields of a new *apiToken.
func tokenFromPrompt() string {
	var token string

	fmt.Println("Let's generate a keyserver certificate from CF API")
	if hostname == "" {
		fmt.Print("Hostname for this Keyless server: ")
		fmt.Scanln(&hostname)
	}
	if zoneID == "" {
		fmt.Print("Cloudflare Zone ID for this Keyless server: ")
		fmt.Scanln(&zoneID)
	}
	fmt.Print("Certificates API Key: ")
	fmt.Scanln(&token)
	return token
}

func getTokenFromFile() string {
	if apiKeyFile == "" {
		return ""
	}

	log.Infof("reading token from file %s", apiKeyFile)
	token, err := ioutil.ReadFile(apiKeyFile)
	if err != nil {
		log.Errorf("Unable to read from file %s: %v", apiKeyFile, err)
	}

	return string(token)
}

func initializeServerCertAndKey() {
	token := getTokenFromFile()
	if len(token) == 0 {
		token = tokenFromPrompt()
	}

	csr, key, err := generateCSR(hostname)
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

	log.Info("contacting Cloudflare API for CSR signing")

	cert, err := initAPICall(token, hostname, zoneID, string(csr))
	if err != nil {
		log.Fatal("initialization failed due to API error:", err)
	}

	if err := os.Remove(certFile); err != nil && !os.IsNotExist(err) {
		log.Fatal("couldn't remove old certificate file: ", err)
	}

	if err := ioutil.WriteFile(certFile, cert, 0644); err != nil {
		log.Fatal("couldn't write to certificate file: ", err)
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
