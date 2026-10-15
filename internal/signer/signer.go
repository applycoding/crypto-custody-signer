// Package signer keeps secp256k1 signing keys behind a Backend interface.
//
// Backends:
//   - MemoryHSM: in process, used by default, unit tests and the demo server.
//   - PKCS11 (build tag pkcs11): a real PKCS#11 session, tested in CI against SoftHSM2.
//     Keys are generated or imported as token objects marked non extractable.
package signer

import (
	"errors"
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

// Backend signs 32 byte digests with named secp256k1 keys and returns DER, low S signatures.
type Backend interface {
	ImportKey(label string, key *btcec.PrivateKey) error
	SignDigest(label string, digest []byte) (der []byte, err error)
	PublicKey(label string) (*btcec.PublicKey, error)
}

// ErrNoKey is returned for unknown labels.
var ErrNoKey = errors.New("key not found")

// MemoryHSM is an in memory backend with HSM like semantics: import only, no export.
type MemoryHSM struct {
	mu   sync.Mutex
	keys map[string]*btcec.PrivateKey
}

func NewMemoryHSM() *MemoryHSM { return &MemoryHSM{keys: map[string]*btcec.PrivateKey{}} }

func (s *MemoryHSM) ImportKey(label string, key *btcec.PrivateKey) error {
	if label == "" || key == nil {
		return errors.New("label and key required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.keys[label]; ok {
		return fmt.Errorf("key %s already exists", label)
	}
	s.keys[label] = key
	return nil
}

func (s *MemoryHSM) SignDigest(label string, digest []byte) ([]byte, error) {
	if len(digest) != 32 {
		return nil, errors.New("digest must be 32 bytes")
	}
	s.mu.Lock()
	key, ok := s.keys[label]
	s.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNoKey, label)
	}
	return ecdsa.Sign(key, digest).Serialize(), nil // RFC6979, low S
}

func (s *MemoryHSM) PublicKey(label string) (*btcec.PublicKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key, ok := s.keys[label]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNoKey, label)
	}
	return key.PubKey(), nil
}

// VerifyDigest checks a DER ECDSA signature over a 32 byte digest.
func VerifyDigest(pub *btcec.PublicKey, digest, der []byte) bool {
	sig, err := ecdsa.ParseDERSignature(der)
	if err != nil {
		return false
	}
	return sig.Verify(digest, pub)
}

// RawToLowSDER converts a PKCS#11 raw r||s signature to DER and normalises S to the lower
// half of the curve order, which Bitcoin standardness rules require (BIP 62/146).
func RawToLowSDER(raw []byte) ([]byte, error) {
	if len(raw) != 64 {
		return nil, fmt.Errorf("raw signature must be 64 bytes, got %d", len(raw))
	}
	var r, s btcec.ModNScalar
	if overflow := r.SetByteSlice(raw[:32]); overflow {
		return nil, errors.New("r overflows")
	}
	if overflow := s.SetByteSlice(raw[32:]); overflow {
		return nil, errors.New("s overflows")
	}
	if s.IsOverHalfOrder() {
		s.Negate()
	}
	return ecdsa.NewSignature(&r, &s).Serialize(), nil
}
