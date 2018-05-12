package main

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	yaml "gopkg.in/yaml.v2"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/helpers/derhelpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/gokeyless/server"
)

const (
	defaultEndpoint = "https://api.cloudflare.com/client/v4/certificates/"
)

// Config represents the gokeyless configuration file.
type Config struct {
	LogLevel int `yaml:"loglevel" mapstructure:"loglevel"`

	Hostname     string `yaml:"hostname" mapstructure:"hostname"`
	ZoneID       string `yaml:"zone_id" mapstructure:"zone_id"`
	OriginCAKey  string `yaml:"origin_ca_key" mapstructure:"origin_ca_key"`
	InitEndpoint string `yaml:"init_endpoint" mapstructure:"init_endpoint"`

	CertFile      string `yaml:"cert" mapstructure:"cert"`
	KeyFile       string `yaml:"key" mapstructure:"key"`
	CACertFile    string `yaml:"ca_cert" mapstructure:"ca_cert"`
	CSRFile       string `yaml:"csr" mapstructure:"csr"`
	PrivateKeyDir string `yaml:"private_key_dir" mapstructure:"private_key_dir"`

	Port        int `yaml:"port" mapstructure:"port"`
	MetricsPort int `yaml:"metrics_port" mapstructure:"metrics_port"`

	PidFile string `yaml:"pid_file" mapstructure:"pid_file"`
}

var (
	config Config

	configFile       string
	manualMode       bool
	configMode       bool
	versionMode      bool
	helpMode         bool
	outputConfigMode bool

	version = "dev"
)

func init() {
	flagset := pflag.CommandLine
	flagset.SortFlags = false

	// These flags can all override values from the config file. Hyphens are
	// used for flags (POSIX convention), but they are normalized to underscores
	// (YAML convention) via our pflags normalize function:
	flagset.SetNormalizeFunc(func(f *pflag.FlagSet, name string) pflag.NormalizedName {
		return pflag.NormalizedName(strings.Replace(name, "-", "_", -1))
	})
	flagset.IntP("loglevel", "l", 0, "Log level (0 = DEBUG, 5 = FATAL)")
	viper.SetDefault("loglevel", log.LevelInfo)
	flagset.String("hostname", "", "Hostname of this key server (must match configuration in Cloudflare dashboard)")
	flagset.String("zone-id", "", "Cloudflare Zone ID")
	flagset.String("init-endpoint", "", "Cloudflare API endpoint for server initialization")
	viper.SetDefault("init_endpoint", defaultEndpoint)
	flagset.MarkHidden("init-endpoint") // users should not need this
	flagset.String("cert", "", "Key server authentication certificate")
	viper.SetDefault("cert", "server.pem")
	flagset.String("key", "", "Key server authentication key")
	viper.SetDefault("key", "server-key.pem")
	flagset.String("ca-cert", "", "Key client certificate authority")
	viper.SetDefault("ca_cert", "keyless_cacert.pem")
	flagset.String("csr", "", "File to write CSR for server initialization")
	viper.SetDefault("csr", "server.csr")
	flagset.String("private-key-dir", "", "Directory in which private keys are stored with .key extension")
	viper.SetDefault("private_key_dir", "./keys")
	flagset.Int("port", 0, "Port for key server to listen on (must match configuration in Cloudflare dashboard)")
	viper.SetDefault("port", 2407)
	flagset.Int("metrics-port", 0, "Port for key server to serve /metrics")
	viper.SetDefault("metrics_port", 2406)
	flagset.String("pid-file", "", "File to store PID of running server")

	// These are control flags which do not have configuration file
	// counterparts.
	flagset.StringVarP(&configFile, "config-file", "c", "", "Configuration file path")
	flagset.BoolVar(&manualMode, "manual-activation", false, "The keyserver generates key and CSR, and exits. Use the CSR to get server certificate issued manually.")
	flagset.MarkHidden("manual-activation") // users should not need this
	flagset.BoolVar(&configMode, "config-only", false, "Perform interactive configuration, but do not run server")
	flagset.BoolVarP(&versionMode, "version", "v", false, "Print version and exit")
	flagset.BoolVarP(&helpMode, "help", "h", false, "Print usage exit")
	// Temporary option to demo config overrides.
	flagset.BoolVarP(&outputConfigMode, "output-config", "o", false, "Print usage exit")
	flagset.MarkHidden("output_config")
}

func initConfig() error {
	pflag.Parse()
	viper.BindPFlags(pflag.CommandLine)
	viper.AutomaticEnv()

	viper.SetConfigType("yaml")
	if configFile != "" {
		viper.SetConfigFile(configFile)
	} else {
		viper.SetConfigName("gokeyless")
		// Check for a config file in the current directory first, then fallback
		// to the system wide location.
		viper.AddConfigPath(".")
		viper.AddConfigPath("/etc/keyless")
	}

	if err := viper.ReadInConfig(); err != nil {
		// File not found is non-fatal, unless it was explicitly provided.
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok || configFile != "" {
			return err
		}
	}

	return viper.Unmarshal(&config)
}

func main() {
	if err := initConfig(); err != nil {
		log.Fatal(err)
	}
	log.Level = config.LogLevel

	switch {
	case helpMode:
		pflag.Usage()
		os.Exit(0)
	case versionMode:
		fmt.Println("gokeyless version", version)
		os.Exit(0)
	case manualMode && configMode:
		log.Fatal("can't specify both -manual-activation and -config-only!")
	case manualMode:
		// Allow manual activation (requires the CSR to be manually signed).
		// manual activation won't proceed to start the server
		log.Info("now check server csr and key")
		if !verifyCSRAndKey() {
			log.Info("csr and key are not usable. generating server csr and key")
			manualActivation()

			log.Infof("contact CloudFlare for manual signing of csr in %q",
				config.CSRFile)
		} else {
			log.Infof("csr at %q and private key at %q are already generated and verified correctly, please contact CloudFlare for manual signing",
				config.CSRFile, config.KeyFile)
		}
		os.Exit(0)
	case configMode:
		if needNewCertAndKey() {
			initializeServerCertAndKey()
		} else {
			log.Info("already configured; exiting")
		}
		os.Exit(0)
	case outputConfigMode:
		b, err := yaml.Marshal(config)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Print(string(b))
		os.Exit(0)
	}

	// If we make it here we need to ask for user input, so we need to give up
	// and log an error instead (in case the server is running as a daemon).
	// Failing hard with an error message makes the problem obvious, whereas a
	// daemon blocked waiting on input can be hard to debug.
	if needNewCertAndKey() {
		log.Error("the server cert/key need to be generated; set the hostname, zone_id, and origin_ca_key values in your config file, or run the server with either the -config-only or -manual-activation flag to generate the pair interactively")
		os.Exit(1)
	}

	cfg := server.DefaultServeConfig()
	s, err := server.NewServerFromFile(cfg, config.CertFile, config.KeyFile, config.CACertFile)
	if err != nil {
		log.Fatal("cannot start server:", err)
	}

	keys, err := server.NewKeystoreFromDir(config.PrivateKeyDir, LoadKey)
	if err != nil {
		log.Fatal(err)
	}

	s.SetKeystore(keys)

	if config.PidFile != "" {
		if f, err := os.Create(config.PidFile); err != nil {
			log.Fatalf("error creating pid file: %v", err)
		} else {
			fmt.Fprintf(f, "%d", os.Getpid())
			f.Close()
		}
	}

	go func() {
		log.Critical(s.MetricsListenAndServe(net.JoinHostPort("", strconv.Itoa(config.MetricsPort))))
	}()
	log.Fatal(s.ListenAndServe(net.JoinHostPort("", strconv.Itoa(config.Port))))
}

// LoadKey attempts to load a private key from PEM or DER.
func LoadKey(in []byte) (priv crypto.Signer, err error) {
	priv, err = helpers.ParsePrivateKeyPEM(in)
	if err == nil {
		return priv, nil
	}

	return derhelpers.ParsePrivateKeyDER(in)
}

// validCertExpiry checks if cerficiate is currently valid.
func validCertExpiry(cert *x509.Certificate) bool {
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return false
	}

	if now.After(cert.NotAfter) {
		return false
	}

	// certificate expires in a month
	if now.Add(time.Hour * 24 * 30).After(cert.NotAfter) {
		log.Warning("server certificate is expiring in 30 days")
	}

	return true
}

// needNewCertAndKey checks the validity of certificate and key
func needNewCertAndKey() bool {
	_, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		log.Errorf("cannot load server cert/key: %v", err)
		return true
	}

	// error is ignore because tls.LoadX509KeyPair already verify the existence of the file
	certBytes, _ := ioutil.ReadFile(config.CertFile)
	// error is ignore because tls.LoadX509KeyPair already verify the file can be parsed
	cert, _ := helpers.ParseCertificatePEM(certBytes)
	// verify the leaf certificate
	if cert == nil || !validCertExpiry(cert) {
		log.Errorf("certificate is either not yet valid or expired")
		return true
	}

	return false
}

// verifyCSRAndKey checks if csr and key files exist and if they match
func verifyCSRAndKey() bool {
	csrBytes, err := ioutil.ReadFile(config.CSRFile)
	if err != nil {
		log.Errorf("cannot read csr file: %v", err)
		return false
	}

	csr, err := helpers.ParseCSRPEM(csrBytes)
	if err != nil {
		log.Errorf("cannot parse csr file: %v", err)
		return false
	}

	if err := csr.CheckSignature(); err != nil {
		log.Errorf("cannot verify csr signature: %v", err)
		return false
	}

	csrPubKey, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		log.Errorf("cannot serialize public key from csr: %v", err)
		return false
	}

	keyBytes, err := ioutil.ReadFile(config.KeyFile)
	if err != nil {
		log.Errorf("cannot read private key file: %v", err)
		return false
	}

	key, err := helpers.ParsePrivateKeyPEM(keyBytes)
	if err != nil {
		log.Errorf("cannot parse private key file: %v", err)
		return false
	}

	pubkey, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		log.Errorf("cannot serialize public key from private key: %v", err)
		return false
	}

	if !bytes.Equal(pubkey, csrPubKey) {
		log.Errorf("csr doesn't match with private key")
		return false
	}

	return true
}
