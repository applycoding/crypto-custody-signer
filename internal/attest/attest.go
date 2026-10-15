// Package attest signs policy decisions so the transaction signer can check that a
// withdrawal really passed the policy engine. The production path uses HashiCorp Vault's
// transit engine with an ed25519 key (a type transit supports natively), so the attestation
// key never lives in the custody process.
package attest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Attestor signs and verifies byte messages.
type Attestor interface {
	Sign(msg []byte) (string, error)
	Verify(msg []byte, sig string) (bool, error)
}

// Local is an in process ed25519 attestor for tests and the offline demo.
type Local struct{ priv ed25519.PrivateKey }

func NewLocal() *Local {
	_, priv, _ := ed25519.GenerateKey(nil)
	return &Local{priv}
}

func (l *Local) Sign(msg []byte) (string, error) {
	return "local:v1:" + base64.StdEncoding.EncodeToString(ed25519.Sign(l.priv, msg)), nil
}

func (l *Local) Verify(msg []byte, sig string) (bool, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(sig, "local:v1:"))
	if err != nil {
		return false, nil
	}
	return ed25519.Verify(l.priv.Public().(ed25519.PublicKey), msg, raw), nil
}

// VaultTransit uses Vault's REST API: /v1/<mount>/keys, /sign and /verify.
type VaultTransit struct {
	Addr, Token, Mount, Key string
	HTTP                    *http.Client
}

func NewVaultTransit(addr, token, key string) *VaultTransit {
	return &VaultTransit{Addr: strings.TrimRight(addr, "/"), Token: token, Mount: "transit", Key: key, HTTP: &http.Client{Timeout: 5 * time.Second}}
}

func (v *VaultTransit) do(method, path string, body any) (map[string]any, error) {
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, fmt.Sprintf("%s/v1/%s/%s", v.Addr, v.Mount, path), rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", v.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := v.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("vault %s %s: %d %s", method, path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if len(raw) == 0 {
		return map[string]any{}, nil
	}
	var out struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out.Data, nil
}

// EnsureKey creates the ed25519 transit key if it does not exist (idempotent in Vault).
func (v *VaultTransit) EnsureKey() error {
	_, err := v.do(http.MethodPost, "keys/"+v.Key, map[string]any{"type": "ed25519"})
	return err
}

func (v *VaultTransit) Sign(msg []byte) (string, error) {
	d, err := v.do(http.MethodPost, "sign/"+v.Key, map[string]any{"input": base64.StdEncoding.EncodeToString(msg)})
	if err != nil {
		return "", err
	}
	sig, ok := d["signature"].(string)
	if !ok {
		return "", errors.New("vault response missing signature")
	}
	return sig, nil
}

func (v *VaultTransit) Verify(msg []byte, sig string) (bool, error) {
	d, err := v.do(http.MethodPost, "verify/"+v.Key, map[string]any{"input": base64.StdEncoding.EncodeToString(msg), "signature": sig})
	if err != nil {
		return false, err
	}
	ok, _ := d["valid"].(bool)
	return ok, nil
}
