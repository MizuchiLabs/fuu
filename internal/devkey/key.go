// Package devkey is this machine's TPM-resident ECDH P-256 identity, derived fresh from the owner seed on every open so nothing is ever persisted, with no software fallback when no TPM can be opened.
package devkey

import (
	"crypto/ecdh"
	"errors"
	"fmt"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Key is this machine's device key, and its private half never leaves the TPM.
type Key struct {
	tpm transport.TPMCloser
	key *primaryKey
	mu  sync.Mutex
}

// Open derives this machine's device key, and a missing or unusable TPM is a hard error rather than a fallback.
func Open() (*Key, error) {
	dev, err := openTPMDevice()
	if err != nil {
		return nil, fmt.Errorf("devkey: open tpm: %w", err)
	}
	key, err := createPrimary(dev)
	if err != nil {
		return nil, errors.Join(err, dev.Close())
	}
	return &Key{tpm: dev, key: key}, nil
}

// Public returns the public half of the device key.
func (k *Key) Public() *ecdh.PublicKey {
	return k.key.pub
}

// ECDH multiplies the device key by peer inside the TPM and returns the shared X coordinate.
func (k *Key) ECDH(peer *ecdh.PublicKey) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return ecdhZGen(k.tpm, k.key, peer)
}

// Close flushes the key handle and closes the TPM transport.
func (k *Key) Close() error {
	_, err := tpm2.FlushContext{FlushHandle: k.key.hnd}.Execute(k.tpm)
	return errors.Join(err, k.tpm.Close())
}
