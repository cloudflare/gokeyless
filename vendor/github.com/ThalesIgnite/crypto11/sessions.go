// Copyright 2016, 2017 Thales e-Security, Inc
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package crypto11

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/miekg/pkcs11"
	"github.com/youtube/vitess/go/pools"
)

const (
	idleTimeout       = 0 * time.Second // disable closing of idle sessions, see https://github.com/ThalesIgnite/crypto11/issues/9
	newSessionTimeout = 15 * time.Second
)

// PKCS11Session contains a reference to a loaded PKCS#11 RSA session handle.
type PKCS11Session struct {
	Handle pkcs11.SessionHandle
}

// Map of slot IDs to session pools
var sessionPools = map[uint]*pools.ResourcePool{}

// Mutex protecting sessionPools
var sessionPoolMutex sync.RWMutex

// Create a new session for a given slot
func newSession(slot uint) (*PKCS11Session, error) {
	session, err := libHandle.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, err
	}
	return &PKCS11Session{session}, nil
}

// Close closes the session.
func (session *PKCS11Session) Close() {
	libHandle.CloseSession(session.Handle)
}

// Run a function with a session
//
// setupSessions must have been called for the slot already, otherwise
// an error will be returned.
func withSession(slot uint, f func(session *PKCS11Session) error) error {
	sessionPoolMutex.RLock()
	sessionPool := sessionPools[slot]
	sessionPoolMutex.RUnlock()
	if sessionPool == nil {
		return fmt.Errorf("crypto11: no session for slot %d", slot)
	}

	ctx, cancel := context.WithTimeout(context.Background(), newSessionTimeout)
	defer cancel()

	session, err := sessionPool.Get(ctx)
	if err != nil {
		return err
	}
	defer sessionPool.Put(session)

	return f(session.(*PKCS11Session))
}

// Create the session pool for a given slot if it does not exist
// already.
func setupSessions(slot uint) error {
	sessionPoolMutex.Lock()
	if _, ok := sessionPools[slot]; !ok {
		sessionPools[slot] = pools.NewResourcePool(
			func() (pools.Resource, error) {
				return newSession(slot)
			},
			maxSessions,
			maxSessions,
			idleTimeout,
		)
	}
	sessionPoolMutex.Unlock()

	return nil
}
