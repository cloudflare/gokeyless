package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/opentracing/opentracing-go"
	"github.com/uber/jaeger-client-go"

	"github.com/spf13/afero"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/gokeyless/certmetrics"
	"github.com/cloudflare/gokeyless/server"
	log "github.com/sirupsen/logrus"
)

const (
	defaultEndpoint = "https://api.cloudflare.com/client/v4/certificates/"
)

func (c *Config) initializeWithDefaults() {
	c.fs = afero.NewOsFs()
	c.reader = os.Stdin
}

// Config represents the gokeyless configuration file.
type Config struct {
	LogLevel int `yaml:"loglevel" mapstructure:"loglevel"`

	Hostname     string `yaml:"hostname" mapstructure:"hostname"`
	ZoneID       string `yaml:"zone_id" mapstructure:"zone_id"`
	OriginCAKey  string `yaml:"origin_ca_api_key" mapstructure:"origin_ca_api_key"`
	InitEndpoint string `yaml:"init_endpoint" mapstructure:"init_endpoint"`

	fs         afero.Fs
	reader     io.Reader
	CertFile   string `yaml:"auth_cert" mapstructure:"auth_cert"`
	KeyFile    string `yaml:"auth_key" mapstructure:"auth_key"`
	CSRFile    string `yaml:"auth_csr" mapstructure:"auth_csr"`
	CACertFile string `yaml:"cloudflare_ca_cert" mapstructure:"cloudflare_ca_cert"`

	PrivateKeyStores []PrivateKeyStoreConfig `yaml:"private_key_stores" mapstructure:"private_key_stores"`

	Port        int `yaml:"port" mapstructure:"port"`
	MetricsPort int `yaml:"metrics_port" mapstructure:"metrics_port"`

	PidFile string `yaml:"pid_file" mapstructure:"pid_file"`

	CurrentTime string `yaml:"current_time" mapstructure:"current_time"`

	TracingEnabled    bool    `yaml:"tracing_enabled" mapstructure:"tracing_enabled"`
	TracingAddress    string  `yaml:"tracing_address" mapstructure:"tracing_address"`
	TracingSampleRate float64 `yaml:"tracing_sample_rate" mapstructure:"tracing_sample_rate"` // between 0 and 1
}

// PrivateKeyStoreConfig defines a key store.
type PrivateKeyStoreConfig struct {
	Dir  string `yaml:"dir,omitempty" mapstructure:"dir"`
	File string `yaml:"file,omitempty" mapstructure:"file"`
	URI  string `yaml:"uri,omitempty" mapstructure:"uri"`
}

var (
	config Config

	privateKeyDirs  string
	privateKeyFiles string
	currentTime     time.Time

	configFile       string
	manualMode       bool
	configMode       bool
	versionMode      bool
	helpMode         bool
	outputConfigMode bool
	keystoreDbgMode  bool

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
	viper.SetDefault("loglevel", log.InfoLevel)
	flagset.String("hostname", "", "Hostname of this key server (must match configuration in Cloudflare dashboard)")
	flagset.String("zone-id", "", "Cloudflare Zone ID")
	flagset.String("origin_ca_api_key", "", "Cloudflare Origin CA API key")
	flagset.String("init-endpoint", "", "Cloudflare API endpoint for server initialization")
	viper.SetDefault("init_endpoint", defaultEndpoint)
	flagset.MarkHidden("init-endpoint") // users should not need this
	flagset.String("auth-cert", "", "Key server authentication certificate")
	viper.SetDefault("auth_cert", "server.pem")
	flagset.String("auth-key", "", "Key server authentication key")
	viper.SetDefault("auth_key", "server-key.pem")
	flagset.String("auth-csr", "", "File to write CSR for server authentication certificate initialization")
	viper.SetDefault("auth_csr", "server.csr")
	flagset.String("cloudflare-ca-cert", "", "Key client certificate authority (key clients run on Cloudflare's edge servers)")
	viper.SetDefault("cloudflare_ca_cert", "keyless_cacert.pem")
	flagset.Int("port", 0, "Port for key server to listen on (must match configuration in Cloudflare dashboard)")
	viper.SetDefault("port", 2407)
	flagset.Int("metrics-port", 0, "Port for key server to serve /metrics")
	viper.SetDefault("metrics_port", 2406)
	flagset.String("pid-file", "", "File to store PID of running server")
	flagset.String("current-time", "", "Current time used for certificate validation (for testing only)")
	flagset.Bool("tracing-enabled", false, "")
	flagset.String("tracing-address", "", "")
	viper.SetDefault("tracing-address", "localhost:6831")
	flagset.Float64("tracing-sample-rate", 0, "")
	// These override the private_key_stores value from the config file.
	flagset.StringVar(&privateKeyDirs, "private-key-dirs", "", "Comma-separated list of directories in which private keys are stored with .key extension")
	flagset.StringVar(&privateKeyFiles, "private-key-files", "", "Comma-separated list of private key files")

	// These are control flags which do not have configuration file
	// counterparts.
	flagset.StringVarP(&configFile, "config-file", "c", "", "Configuration file path")
	flagset.BoolVar(&manualMode, "manual-activation", false, "The keyserver generates key and CSR, and exits. Use the CSR to get server certificate issued manually.")
	flagset.MarkHidden("manual-activation") // users should not need this
	flagset.BoolVar(&configMode, "config-only", false, "Perform interactive configuration, but do not run server")
	flagset.BoolVarP(&versionMode, "version", "v", false, "Print version and exit")
	flagset.BoolVarP(&helpMode, "help", "h", false, "Print usage exit")
	flagset.BoolVarP(&keystoreDbgMode, "keystore-debug", "d", false, "try to connect to the defined keystores")
	// Temporary option to demo config overrides.
	flagset.BoolVarP(&outputConfigMode, "output-config", "o", false, "Print usage exit")
	flagset.MarkHidden("output_config")
}

func initConfig() error {
	pflag.Parse()
	if err := viper.BindPFlags(pflag.CommandLine); err != nil {
		return err
	}
	viper.AutomaticEnv()
	viper.SetEnvPrefix("KEYLESS")

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

	if err := viper.Unmarshal(&config); err != nil {
		return err
	}

	// Validate the config.
	if config.CurrentTime != "" {
		var err error
		currentTime, err = time.Parse(time.RFC3339, config.CurrentTime)
		if err != nil {
			return fmt.Errorf("invalid time format for --current-time")
		}
	}

	for _, store := range config.PrivateKeyStores {
		if (store.Dir != "" && store.File == "" && store.URI == "") ||
			(store.Dir == "" && store.File != "" && store.URI == "") ||
			(store.Dir == "" && store.File == "" && store.URI != "") {
			continue
		}
		return fmt.Errorf("private key stores must define exactly one of the 'dir', 'file', or 'uri' keys")
	}

	// Special handling for private key override flags since the config file
	// uses a slice of structs.
	if privateKeyDirs != "" || privateKeyFiles != "" {
		var dirs, files []string
		if privateKeyDirs != "" {
			dirs = strings.Split(strings.TrimSpace(privateKeyDirs), ",")
		}
		if privateKeyFiles != "" {
			files = strings.Split(strings.TrimSpace(privateKeyFiles), ",")
		}
		config.PrivateKeyStores = make([]PrivateKeyStoreConfig, 0, len(dirs)+len(files))
		for _, dir := range dirs {
			config.PrivateKeyStores = append(config.PrivateKeyStores, PrivateKeyStoreConfig{Dir: dir})
		}
		for _, file := range files {
			config.PrivateKeyStores = append(config.PrivateKeyStores, PrivateKeyStoreConfig{File: file})
		}
	}

	return nil
}
func main() {
	if err := runMain(); err != nil {
		log.Fatal(err)
	}
}
func runMain() error {
	if err := initConfig(); err != nil {
		return err
	}
	config.initializeWithDefaults()
	log.SetLevel(parseLogrusLevel(config.LogLevel))
	switch {
	case helpMode:
		pflag.Usage()
		return nil
	case versionMode:
		fmt.Println("gokeyless version", version)
		if info, ok := debug.ReadBuildInfo(); ok {
			fmt.Printf("%s built with %s\n", info.Path, info.GoVersion)
		}

		return nil
	case manualMode && configMode:
		return fmt.Errorf("can't specify both --manual-activation and --config-only!")
	case manualMode:
		// Allow manual activation (requires the CSR to be manually signed).
		// manual activation won't proceed to start the server
		log.Info("now check server csr and key")
		if !config.verifyCSRAndKey() {
			log.Info("csr and key are not usable. generating server csr and key")
			config.manualActivation()

			log.Infof("contact Cloudflare for manual signing of csr in %q",
				config.CSRFile)
		} else {
			log.Infof("csr at %q and private key at %q are already generated and verified correctly, please contact Cloudflare for manual signing",
				config.CSRFile, config.KeyFile)
		}
		return nil
	case configMode:
		if config.needNewCertAndKey() {
			if err := config.initializeServerCertAndKey(); err != nil {
				log.Fatalf("failed to initialize: %s", err)
			}
		} else {
			log.Info("already configured; exiting")
		}
		return nil
	case outputConfigMode:
		b, err := yaml.Marshal(config)
		if err != nil {
			return err
		}
		fmt.Print(string(b))
		return nil

	case keystoreDbgMode:
		log.SetLevel(log.DebugLevel)

		_, err := initKeyStore(config.PrivateKeyStores...)
		return err

	}

	if config.TracingEnabled {
		// jaeger failing to connect to the agent / initializing shouldn't prevent keyless from starting,
		// so if we encounter an error we should log it but move on.
		jaegerTransport, err := jaeger.NewUDPTransport(config.TracingAddress, 0)
		if err != nil {
			log.Errorf("failed to enable tracing: %s", err)
		}
		sampler, err := jaeger.NewProbabilisticSampler(config.TracingSampleRate)
		if err != nil {
			log.Errorf("failed to enable tracing: %s", err)
		}
		tracer, closer := jaeger.NewTracer("gokeyless", sampler, jaeger.NewRemoteReporter(jaegerTransport))
		defer closer.Close()
		opentracing.SetGlobalTracer(tracer)
		log.Infof("tracing enabled: %s", sampler.String())
	}

	// If we make it here we need to ask for user input, so we need to give up
	// and log an error instead (in case the server is running as a daemon).
	// Failing hard with an error message makes the problem obvious, whereas a
	// daemon blocked waiting on input can be hard to debug.
	if config.needNewCertAndKey() {
		if config.needInteractivePrompt() {
			return fmt.Errorf("the server cert/key need to be generated; set the hostname, zone_id, and origin_ca_api_key values in your config file, or run the server with either the --config-only or --manual-activation flag to generate the pair interactively")
		}
		if err := config.initializeServerCertAndKey(); err != nil {
			log.Fatalf("failed to initialize: %s", err)
		}
	}

	cfg := server.DefaultServeConfig()
	s, err := server.NewServerFromFile(cfg, config.CertFile, config.KeyFile, config.CACertFile)
	if err != nil {
		return fmt.Errorf("cannot start server: %w", err)
	}

	if !currentTime.IsZero() {
		s.TLSConfig().Time = func() time.Time { return currentTime }
	}

	keys, err := initKeyStore(config.PrivateKeyStores...)
	if err != nil {
		return err
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
	certs, err := certmetrics.GatherFromPaths([]string{
		config.CertFile,
		config.CACertFile,
	})
	if err != nil {
		return err
	}
	certmetrics.Observe(certs...)
	go func() {
		log.Error(s.MetricsListenAndServe(net.JoinHostPort("", strconv.Itoa(config.MetricsPort))))
	}()
	return s.ListenAndServe(net.JoinHostPort("", strconv.Itoa(config.Port)))
}

func initKeyStore(privateKeyStores ...PrivateKeyStoreConfig) (server.Keystore, error) {
	keys := server.NewDefaultKeystore()
	for _, store := range privateKeyStores {
		switch {
		case store.Dir != "":
			if err := keys.AddFromDir(store.Dir, server.DefaultLoadKey); err != nil {
				return nil, err
			}
		case store.File != "":
			if err := keys.AddFromFile(store.File, server.DefaultLoadKey); err != nil {
				return nil, err
			}
		case store.URI != "":
			if err := keys.AddFromURI(store.URI); err != nil {
				return nil, err
			}
		}
	}
	return keys, nil
}

// validCertExpiry checks if certificate is currently valid.
func validCertExpiry(cert *x509.Certificate) bool {
	now := currentTime
	if currentTime.IsZero() {
		now = time.Now()
	}
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
func (config Config) needNewCertAndKey() bool {
	_, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		log.Errorf("cannot load server cert/key: %v", err)
		return true
	}

	// error is ignore because tls.LoadX509KeyPair already verify the existence of the file
	certBytes, _ := os.ReadFile(config.CertFile)
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
func (config Config) verifyCSRAndKey() bool {
	csrBytes, err := os.ReadFile(config.CSRFile)
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

	keyBytes, err := os.ReadFile(config.KeyFile)
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
func parseLogrusLevel(input int) log.Level {
	// 0 = DEBUG, 5 = FATAL
	switch input {
	case 0:
		return log.DebugLevel
	case 1:
		return log.InfoLevel
	case 2:
		return log.WarnLevel
	case 3:
		return log.ErrorLevel
	case 4:
		// old logger had a 'critical level' in between error and fatal that was unused
		// this maintains backwards compatabiity of the log level numbers in existing configs
		return log.FatalLevel
	case 5:
		return log.FatalLevel
	default:
		return log.InfoLevel
	}
}
