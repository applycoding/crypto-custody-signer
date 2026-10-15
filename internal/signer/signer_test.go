package signer_test

import (
	"crypto/sha256"
	"testing"

	"github.com/applycoding/crypto-custody-signer/internal/signer"
	"github.com/btcsuite/btcd/btcec/v2"
)

// BackendContract is shared by the memory and PKCS#11 tests.
func BackendContract(t *testing.T, b signer.Backend, label string) {
	t.Helper()
	key, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := b.ImportKey(label, key); err != nil {
		t.Fatal(err)
	}
	if err := b.ImportKey(label, key); err == nil {
		t.Fatal("duplicate import accepted")
	}
	pub, err := b.PublicKey(label)
	if err != nil {
		t.Fatal(err)
	}
	if !pub.IsEqual(key.PubKey()) {
		t.Fatal("public key mismatch")
	}
	for i := 0; i < 20; i++ {
		digest := sha256.Sum256([]byte{byte(i), 'c', 'u', 's', 't'})
		sig, err := b.SignDigest(label, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		if !signer.VerifyDigest(pub, digest[:], sig) {
			t.Fatal("signature does not verify")
		}
		other := sha256.Sum256([]byte("other"))
		if signer.VerifyDigest(pub, other[:], sig) {
			t.Fatal("signature verified for wrong digest")
		}
	}
	if _, err := b.SignDigest(label, []byte("short")); err == nil {
		t.Fatal("short digest accepted")
	}
	if _, err := b.SignDigest(label+"-missing", make([]byte, 32)); err == nil {
		t.Fatal("missing key signed")
	}
}

func TestMemoryHSM(t *testing.T) { BackendContract(t, signer.NewMemoryHSM(), "wallet-0") }

func TestRawToLowSDER(t *testing.T) {
	// s = n - 1 is over half order and must be negated to 1.
	raw := make([]byte, 64)
	raw[31] = 1
	var n1 btcec.ModNScalar
	n1.SetInt(1)
	n1.Negate()
	b := n1.Bytes()
	copy(raw[32:], b[:])
	der, err := signer.RawToLowSDER(raw)
	if err != nil {
		t.Fatal(err)
	}
	// DER: 30 06 02 01 01 02 01 01
	if len(der) != 8 || der[7] != 1 {
		t.Fatalf("not normalised: %x", der)
	}
	if _, err := signer.RawToLowSDER(raw[:10]); err == nil {
		t.Fatal("short raw accepted")
	}
}
