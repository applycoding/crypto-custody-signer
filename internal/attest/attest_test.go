package attest_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/applycoding/crypto-custody-signer/internal/attest"
)

func contract(t *testing.T, a attest.Attestor) {
	t.Helper()
	msg := []byte(`{"withdrawal":"wd_1","amount_sats":1000}`)
	sig, err := a.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := a.Verify(msg, sig); err != nil || !ok {
		t.Fatalf("valid signature rejected: %v", err)
	}
	if ok, _ := a.Verify([]byte(`{"withdrawal":"wd_1","amount_sats":9999}`), sig); ok {
		t.Fatal("tampered message accepted")
	}
}

func TestLocal(t *testing.T) { contract(t, attest.NewLocal()) }

// fakeVault implements the three transit endpoints used, following Vault's response shape.
func fakeVault(t *testing.T) *httptest.Server {
	_, priv, _ := ed25519.GenerateKey(nil)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "root" {
			http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
			return
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		msg, _ := base64.StdEncoding.DecodeString(body["input"])
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/transit/keys/"):
			w.WriteHeader(http.StatusNoContent)
		case strings.HasPrefix(r.URL.Path, "/v1/transit/sign/"):
			sig := "vault:v1:" + base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"signature": sig}})
		case strings.HasPrefix(r.URL.Path, "/v1/transit/verify/"):
			raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(body["signature"], "vault:v1:"))
			ok := ed25519.Verify(priv.Public().(ed25519.PublicKey), msg, raw)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"valid": ok}})
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestVaultTransitAgainstFake(t *testing.T) {
	srv := fakeVault(t)
	defer srv.Close()
	v := attest.NewVaultTransit(srv.URL, "root", "custody-policy")
	if err := v.EnsureKey(); err != nil {
		t.Fatal(err)
	}
	contract(t, v)
	bad := attest.NewVaultTransit(srv.URL, "wrong", "custody-policy")
	if _, err := bad.Sign([]byte("x")); err == nil {
		t.Fatal("bad token accepted")
	}
}

// Runs against a real Vault dev server when VAULT_ADDR is set (CI starts one).
func TestVaultTransitReal(t *testing.T) {
	addr := os.Getenv("VAULT_ADDR")
	if addr == "" {
		t.Skip("VAULT_ADDR not set")
	}
	v := attest.NewVaultTransit(addr, os.Getenv("VAULT_TOKEN"), "custody-policy")
	if err := v.EnsureKey(); err != nil {
		t.Fatal(err)
	}
	contract(t, v)
}
