package server

import (
	"crypto/rand"
	"io"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/cloudflare/gokeyless/internal/test/params"
)

var samples = `pkcs11:id=0
pkcs11:id=0;token=b
pkcs11:id=b?pin-value=1234
pkcs11:id=b?pin-value=1234&module-path=/a/b.so
pkcs11:id=b;token=b?pin-value=1234&module-path=/a/b.so
pkcs11:token=Thalesn6000;id=%00?module-path=/opt/nfast/toolkits/pkcs11/libcknfast.so&pin-value=1234
pkcs11:token=SoftHSM2;id=%00;slot-id=1359138056?module-path=/usr/lib64/libsofthsm2.so&pin-value=1234
pkcs11:token=YubiKey%20PIV;id=%00;slot-id=0?module-path=/usr/lib64/libykcs11.so&pin-value=123456
pkcs11:token=Gemalto;id=%04;slot-id=0?module-path=/usr/lib/libCryptoki2_64.so&pin-value=abcd`

// TODO add false tests too

func TestParser(t *testing.T) {
	tests := strings.Split(samples, "\n")
	for _, test := range tests {
		pk11uri := RFC7512Parser(test)
		if len(pk11uri.Id) == 0 {
			t.Fail()
		}
	}
}

func TestHSMSignConcurrencyRSASHA512(t *testing.T) {
	if os.Getenv("TESTHSM") == "" {
		t.Skip("skipping test; $TESTHSM not set")
	}

	p := params.HSMRSASHA512Params
	pk11uri := RFC7512Parser(p.URI)
	key, err := LoadPKCS11Key(pk11uri)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, p.PayloadSize)
	_, err = io.ReadFull(rand.Reader, payload[:])
	if err != nil {
		t.Fatal(err)
	}

	const n = 2000
	const m = 10

	// The barrier is used to ensure that goroutines only start running once we
	// release them - we don't want any getting a head start and finishing
	// before others are started.
	var barrier, wg sync.WaitGroup
	barrier.Add(1)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			barrier.Wait()
			for i := 0; i < m; i++ {
				_, err := key.Sign(rand.Reader, payload, p.Opts)
				if err != nil {
					t.Fatal(err)
				}
			}
			wg.Done()
		}()
	}

	barrier.Done()
	wg.Wait()
}
