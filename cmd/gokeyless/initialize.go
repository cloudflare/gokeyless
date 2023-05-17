package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cloudflare-go"
	"github.com/spf13/afero"
)

type initAPIRequest struct {
	Rqtype    string   `json:"request_type,omitempty"`
	Hostnames []string `json:"hostnames,omitempty"`
	ZoneID    string   `json:"zone_id,omitempty"`
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
	cloudflare.Response
	// todo: use https://github.com/cloudflare/cloudflare-go/blob/master/origin_ca.go for this whole struct
	Result map[string]string `json:"result,omitempty"`
}

func (config *Config) initAPICall(token, hostname, zoneID, csr string) ([]byte, error) {
	body, err := newRequestBody(hostname, zoneID, csr)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", config.InitEndpoint, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-Auth-User-Service-Key", token)

	log.Infof("making API call: %s", config.InitEndpoint)
	resp, err := new(http.Client).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("certificate API returned an invalid response body for HTTP %d", resp.StatusCode)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("certificate API returns non-200 response, HTTP code: %d, Response: %s", resp.StatusCode, string(bodyBytes))
	}
	apiResp := &initAPIResponse{}
	err = json.Unmarshal(bodyBytes, apiResp)
	if err != nil {
		return nil, fmt.Errorf("unable to parse certificate API response (%w) HTTP Response: %s", err, string(bodyBytes))
	}

	if !apiResp.Success {
		return nil, fmt.Errorf("certificate API call returns errors: %s", string(bodyBytes))
	}

	if cert, ok := apiResp.Result["certificate"]; ok {
		return []byte(cert), nil
	}

	return nil, fmt.Errorf("no certificate in API response: %#v", apiResp)
}

func (config *Config) interactivePrompt() error {
	fmt.Println("Let's generate a keyserver certificate from CF API")
	scanner := bufio.NewScanner(config.reader)

	if config.Hostname == "" {
		fmt.Print("Hostname for this Keyless server: ")
		if scanner.Scan() {
			config.Hostname = scanner.Text()
		}
		if scanner.Err() != nil {
			return scanner.Err()
		}

	}
	if config.ZoneID == "" {
		fmt.Print("Cloudflare Zone ID for this Keyless server: ")
		if scanner.Scan() {
			config.ZoneID = scanner.Text()
		}
		if scanner.Err() != nil {
			return scanner.Err()
		}
	}
	if config.OriginCAKey == "" {
		fmt.Print("Origin CA Key: ")
		if scanner.Scan() {
			config.OriginCAKey = scanner.Text()
		}
		if scanner.Err() != nil {
			return scanner.Err()
		}
	}
	return nil
}

func (config *Config) needInteractivePrompt() bool {
	return config.Hostname == "" || config.ZoneID == "" || config.OriginCAKey == ""
}

func (config *Config) initializeServerCertAndKey() error {
	if config.needInteractivePrompt() {
		if err := config.interactivePrompt(); err != nil {
			return err
		}
	}

	csr, key, err := generateCSR(config.Hostname)
	if err != nil {
		return fmt.Errorf("failed to generate csr and key: %w", err)
	}

	if err := afero.WriteFile(config.fs, config.KeyFile, key, 0600); err != nil {
		return fmt.Errorf("failed to write to key file: %w", err)
	}
	log.Infof("key is generated and saved to %s", config.KeyFile)

	if err := afero.WriteFile(config.fs, config.CSRFile, csr, 0600); err != nil {
		return fmt.Errorf("failed to write to csr file: %w", err)
	}
	log.Infof("csr is generated and saved to %s", config.CSRFile)

	log.Info("contacting Cloudflare API for CSR signing")

	cert, err := config.initAPICall(config.OriginCAKey, config.Hostname, config.ZoneID, string(csr))
	if err != nil {
		return fmt.Errorf("initialization failed due to API error: %w", err)
	}

	if err := config.fs.Remove(config.CertFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("couldn't remove old certificate file: %w", err)
	}

	if err := afero.WriteFile(config.fs, config.CertFile, cert, 0644); err != nil {
		return fmt.Errorf("couldn't write to certificate file: %w", err)
	}
	log.Infof("certificate saved to %s", config.CertFile)

	return nil
}

// generateCSR generates a private key and a CSR for the given host. The
// generated key is persisted to file.
func generateCSR(host string) ([]byte, []byte, error) {
	csr, key, err := csr.ParseRequest(&csr.CertificateRequest{
		CN:    "Keyless Server Authentication Certificate",
		Hosts: []string{host},
		KeyRequest: &csr.KeyRequest{
			A: "ecdsa",
			S: 384,
		},
	})

	return csr, key, err
}

func (config *Config) manualActivation() {
	var host string
	fmt.Print("Keyserver Hostname: ")
	fmt.Scanln(&host)
	csr, key, err := generateCSR(host)
	if err != nil {
		log.Fatal("failed to generate csr and key: ", err)
	}

	if err := os.WriteFile(config.KeyFile, key, 0600); err != nil {
		log.Fatal("failed to write to key file:", err)
	}
	log.Infof("key is generated and saved to %s", config.KeyFile)

	if err := os.WriteFile(config.CSRFile, csr, 0600); err != nil {
		log.Fatal("failed to write to csr file:", err)
	}
	log.Infof("csr is generated and saved to %s", config.CSRFile)
}
