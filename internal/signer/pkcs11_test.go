//go:build pkcs11

package signer_test

import (
	"os"
	"testing"

	"github.com/applycoding/crypto-custody-signer/internal/signer"
)

// Requires SoftHSM2: see scripts/softhsm-init.sh. Run with: go test -tags pkcs11 ./...
func TestPKCS11SoftHSM(t *testing.T) {
	module := os.Getenv("PKCS11_MODULE")
	if module == "" {
		module = "/usr/lib/softhsm/libsofthsm2.so"
	}
	p, err := signer.OpenPKCS11(module, "custody", "1234")
	if err != nil {
		t.Fatalf("open token: %v", err)
	}
	defer p.Close()
	BackendContract(t, p, "imported-"+t.Name())

	if err := p.GenerateKey("generated-" + t.Name()); err != nil {
		t.Fatalf("generate: %v", err)
	}
	pub, err := p.PublicKey("generated-" + t.Name())
	if err != nil {
		t.Fatal(err)
	}
	d := make([]byte, 32)
	d[0] = 7
	sig, err := p.SignDigest("generated-"+t.Name(), d)
	if err != nil || !signer.VerifyDigest(pub, d, sig) {
		t.Fatalf("token generated key failed: %v", err)
	}
}
