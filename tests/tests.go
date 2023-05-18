package tests

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/go-metrics"
	"github.com/cloudflare/gokeyless/client"
)

// Results is a registry of metrics representing the success stats of an entire test suite.
type Results struct {
	metrics.Registry `json:"results"`
	Tests            map[string]*Test `json:"tests"`
}

// NewResults initializes a new API Results registry.
func NewResults() *Results {
	results := &Results{
		Registry: metrics.NewRegistry(),
		Tests:    make(map[string]*Test),
	}
	results.Register("success", metrics.NewCounter())
	results.Register("failure", metrics.NewCounter())
	return results
}

// TestFunc represents generic test to be run.
type TestFunc func() error

// Test represents the success stats for an individual test.
type Test struct {
	metrics.Registry `json:"results"`
	Errors           metrics.Registry `json:"errors,omitempty"`
	run              TestFunc
}

// RegisterTest initializes a new Test struct and adds it to results.
func (results *Results) RegisterTest(name string, run TestFunc) {
	test := &Test{
		Registry: metrics.NewRegistry(),
		Errors:   metrics.NewRegistry(),
		run:      run,
	}
	test.Register("success", metrics.NewCounter())
	test.Register("failure", metrics.NewCounter())
	results.Tests[name] = test
}

// RunTests continually runs the tests stored in results for testLen.
func (results *Results) RunTests(testLen time.Duration, workers int) {
	log.Debugf("Running tests for %v with %d workers", testLen, workers)
	tests := make(chan string, workers)
	for i := 0; i < workers; i++ {
		go func() {
			for name := range tests {
				test := results.Tests[name]
				if err := test.run(); err != nil {
					results.Get("failure").(metrics.Counter).Inc(1)
					test.Get("failure").(metrics.Counter).Inc(1)
					errCount := metrics.GetOrRegisterCounter(err.Error(), test.Errors)
					errCount.Inc(1)
					log.Infof("--- %s - Running %s: %v", "FAIL", name, err)
				} else {
					test.Get("success").(metrics.Counter).Inc(1)
					results.Get("success").(metrics.Counter).Inc(1)
					log.Infof("--- %s - Running %s", "PASS", name)
				}
			}
		}()
	}

	timeout := time.After(testLen)
	for {
		for name := range results.Tests {
			select {
			case <-timeout:
				close(tests)
				return

			case tests <- name:
			}
		}
	}
}

// RunBenchmarkTests runs each tests repetitively with multiple goroutines.
func (results *Results) RunBenchmarkTests(repeats, workers int) {
	log.Debugf("Running each test for %d times with %d workers", repeats, workers)

	var wg sync.WaitGroup
	for name := range results.Tests {
		test := results.Tests[name]
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func(name string, test *Test) {
				defer wg.Done()
				for i := 0; i < repeats; i++ {
					err := test.run()
					if err != nil {
						results.Get("failure").(metrics.Counter).Inc(1)
						test.Get("failure").(metrics.Counter).Inc(1)
						errCount := metrics.GetOrRegisterCounter(err.Error(), test.Errors)
						errCount.Inc(1)
						log.Infof("--- %s - Running %s: %v", "FAIL", name, err)
					} else {
						test.Get("success").(metrics.Counter).Inc(1)
						results.Get("success").(metrics.Counter).Inc(1)
						log.Infof("--- %s - Running %s", "PASS", name)
					}
				}
			}(name, test)
		}
	}

	wg.Wait()
}

// hashPtxt hashes the plaintext with the given hash algorithm.
func hashPtxt(h crypto.Hash, ptxt []byte) []byte {
	return h.New().Sum(ptxt)[len(ptxt):]
}

// NewPingRemoteTest generates a TestFunc to connect and perform a ping to
// a specific remote directly.
func NewPingRemoteTest(c *client.Client, r client.Remote) TestFunc {
	return func() error {
		conn, err := r.Dial(c)
		if err != nil {
			return err
		}
		return conn.Ping(context.Background(), nil)
	}
}

// NewPingTest generates a TestFunc to connect and perform a ping.
func NewPingTest(c *client.Client, server string) TestFunc {
	return func() error {
		r, err := c.LookupServer(server)
		if err != nil {
			return err
		}

		conn, err := r.Dial(c)
		if err != nil {
			return err
		}
		return conn.Ping(context.Background(), nil)
	}
}

// NewSignTests generates a map of test name to TestFunc that performs an opaque sign and verify.
func NewSignTests(priv crypto.Signer) map[string]TestFunc {
	tests := make(map[string]TestFunc)
	ptxt := []byte("Test Plaintext")
	r := rand.Reader
	hashes := map[string]crypto.Hash{
		"sign.md5sha1": crypto.MD5SHA1,
		"sign.sha1":    crypto.SHA1,
		"sign.sha224":  crypto.SHA224,
		"sign.sha256":  crypto.SHA256,
		"sign.sha384":  crypto.SHA384,
		"sign.sha512":  crypto.SHA512,
	}

	for hashName, h := range hashes {
		var msg []byte
		if h == crypto.MD5SHA1 {
			msg = append(hashPtxt(crypto.MD5, ptxt), hashPtxt(crypto.SHA1, ptxt)...)
		} else {
			msg = hashPtxt(h, ptxt)
		}

		tests[hashName] = func(h crypto.Hash) TestFunc {
			return func() error {
				sig, err := priv.Sign(r, msg, h)
				if err != nil {
					return err
				}

				switch pub := priv.Public().(type) {
				case *rsa.PublicKey:
					return rsa.VerifyPKCS1v15(pub, h, msg, sig)
				case *ecdsa.PublicKey:
					ecdsaSig := new(struct{ R, S *big.Int })
					asn1.Unmarshal(sig, ecdsaSig)
					if !ecdsa.Verify(pub, msg, ecdsaSig.R, ecdsaSig.S) {
						return fmt.Errorf("ecdsa verify failed")
					}
				default:
					return fmt.Errorf("unknown public key type")
				}

				return nil
			}
		}(h)
	}
	return tests
}

// NewDecryptTest generates an RSA decryption test.
func NewDecryptTest(decrypter crypto.Decrypter) TestFunc {
	ptxt := []byte("Test Plaintext")
	r := rand.Reader

	return func() (err error) {
		var c, m []byte
		if c, err = rsa.EncryptPKCS1v15(r, decrypter.Public().(*rsa.PublicKey), ptxt); err != nil {
			return
		}

		if m, err = decrypter.Decrypt(r, c, &rsa.PKCS1v15DecryptOptions{}); err != nil {
			return
		}
		if bytes.Compare(ptxt, m) != 0 {
			return fmt.Errorf("rsa decrypt failed")
		}

		if m, err = decrypter.Decrypt(r, c, &rsa.PKCS1v15DecryptOptions{SessionKeyLen: len(ptxt)}); err != nil {
			return
		}
		if bytes.Compare(ptxt, m) != 0 {
			return fmt.Errorf("rsa decrypt failed")
		}

		if m, err = decrypter.Decrypt(r, c, &rsa.PKCS1v15DecryptOptions{SessionKeyLen: len(ptxt) + 1}); err != nil {
			return
		}
		if bytes.Compare(ptxt, m) == 0 {
			return fmt.Errorf("rsa decrypt succeeded despite incorrect SessionKeyLen")
		}
		return nil
	}
}
