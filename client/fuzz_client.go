package client

import "testing"

func FuzzStripPKCS1v15(f *testing.F) {

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = stripPKCS1v15(data)
	})
}

func FuzzStripPKCS1v15SessionKey(f *testing.F) {

	f.Fuzz(func(t *testing.T, data_em []byte, data_key []byte) {
		_ = stripPKCS1v15SessionKey(data_em, data_key)
	})
}
