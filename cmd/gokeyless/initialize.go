package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/log"
	cloudflare "github.com/cloudflare/cloudflare-go"
	"github.com/spf13/afero"
)

// initAPIRequest is the body sent to the Origin CA "certificates" endpoint to
// request a keyless server authentication certificate. Note this carries
// request_type and zone_id, which the typed cloudflare-go
// CreateOriginCACertificate helper does not expose, so we send the request via
// the client's generic Raw method instead.
type initAPIRequest struct {
	Rqtype    string   `json:"request_type,omitempty"`
	Hostnames []string `json:"hostnames,omitempty"`
	ZoneID    string   `json:"zone_id,omitempty"`
	CSR       string   `json:"csr,omitempty"`
}

// newCFClient builds a cloudflare-go API client using whichever credential is
// configured. An API token (preferred) takes precedence over the deprecated
// Origin CA Service Key. The base URL is derived from InitEndpoint so the
// hidden --init-endpoint override keeps working.
func (config *Config) newCFClient() (*cloudflare.API, error) {
	var opts []cloudflare.Option
	if baseURL := deriveBaseURL(config.InitEndpoint); baseURL != "" {
		opts = append(opts, cloudflare.BaseURL(baseURL))
	}

	switch {
	case config.APIToken != "":
		return cloudflare.NewWithAPIToken(config.APIToken, opts...)
	case config.OriginCAKey != "":
		log.Warning("authenticating with the deprecated Origin CA Service Key (origin_ca_api_key); " +
			"please migrate to an API token (api_token / KEYLESS_API_TOKEN) scoped Zone > SSL and Certificates > Edit")
		return cloudflare.NewWithUserServiceKey(config.OriginCAKey, opts...)
	default:
		return nil, fmt.Errorf("no Cloudflare credentials configured: set api_token (preferred) or origin_ca_api_key")
	}
}

// deriveBaseURL converts a full Origin CA certificates endpoint (e.g.
// "https://api.cloudflare.com/client/v4/certificates/") into the base URL
// expected by cloudflare-go (e.g. "https://api.cloudflare.com/client/v4").
// An empty result means "use the library default".
func deriveBaseURL(endpoint string) string {
	if endpoint == "" {
		return ""
	}
	base := strings.TrimSuffix(endpoint, "/")
	base = strings.TrimSuffix(base, "/certificates")
	return strings.TrimSuffix(base, "/")
}

func (config *Config) initAPICall(hostname, zoneID, csr string) ([]byte, error) {
	client, err := config.newCFClient()
	if err != nil {
		return nil, err
	}

	req := initAPIRequest{
		Rqtype:    "keyless-certificate",
		Hostnames: []string{hostname},
		ZoneID:    zoneID,
		CSR:       csr,
	}

	log.Infof("making API call: %s/certificates", deriveBaseURL(config.InitEndpoint))
	// Use Raw rather than the typed CreateOriginCACertificate helper so we can
	// send request_type and zone_id. cloudflare-go applies the configured auth
	// (Bearer token or X-Auth-User-Service-Key) automatically.
	resp, err := client.Raw(context.Background(), http.MethodPost, "/certificates", req, nil)
	if err != nil {
		return nil, fmt.Errorf("certificate API call failed: %w", err)
	}

	var result struct {
		Certificate string `json:"certificate"`
	}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, fmt.Errorf("unable to parse certificate API response (%w): %s", err, string(resp.Result))
	}

	if result.Certificate == "" {
		return nil, fmt.Errorf("no certificate in API response: %s", string(resp.Result))
	}

	return []byte(result.Certificate), nil
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
	// Prefer an API token; only prompt for it when no credential is configured
	// at all. The deprecated Origin CA Service Key continues to work if set.
	if config.APIToken == "" && config.OriginCAKey == "" {
		fmt.Print("Cloudflare API token (scoped Zone > SSL and Certificates > Edit): ")
		if scanner.Scan() {
			config.APIToken = strings.TrimSpace(scanner.Text())
		}
		if scanner.Err() != nil {
			return scanner.Err()
		}
	}
	return nil
}

func (config *Config) hasCredential() bool {
	return config.APIToken != "" || config.OriginCAKey != ""
}

func (config *Config) needInteractivePrompt() bool {
	return config.Hostname == "" || config.ZoneID == "" || !config.hasCredential()
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

	cert, err := config.initAPICall(config.Hostname, config.ZoneID, string(csr))
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
