package api_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/applycoding/crypto-custody-signer/internal/api"
	"github.com/applycoding/crypto-custody-signer/internal/attest"
	"github.com/applycoding/crypto-custody-signer/internal/hdwallet"
	"github.com/applycoding/crypto-custody-signer/internal/policy"
	"github.com/applycoding/crypto-custody-signer/internal/signer"
	"github.com/applycoding/crypto-custody-signer/internal/txbuilder"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

func TestEndToEndCustodyFlow(t *testing.T) {
	w, _ := hdwallet.FromMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "", &chaincfg.TestNet3Params)
	b, _ := txbuilder.New(w)
	hsm := signer.NewMemoryHSM()
	for _, p := range []hdwallet.Path{{}, {Change: 1}} {
		if _, err := txbuilder.ImportPathKey(hsm, w, p); err != nil {
			t.Fatal(err)
		}
	}
	pubA, privA, _ := ed25519.GenerateKey(nil)
	pubB, privB, _ := ed25519.GenerateKey(nil)
	eng, _ := policy.NewEngine(policy.Rules{Tiers: []policy.Tier{{MinAmount: 0, Approvals: 2}}}, []policy.Approver{{ID: "a", PublicKey: pubA}, {ID: "b", PublicKey: pubB}}, nil)
	srv := httptest.NewServer((&api.Service{Engine: eng, Attestor: attest.NewLocal(), HSM: hsm, Builder: b, Wallet: w}).Handler())
	defer srv.Close()

	post := func(path string, body any) (*http.Response, map[string]any) {
		raw, _ := json.Marshal(body)
		resp, err := http.Post(srv.URL+path, "application/json", bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp, out
	}
	dest, _ := w.Address(hdwallet.Path{Index: 7})
	resp, wd := post("/withdrawals", map[string]any{"amount_sats": 30000, "destination": dest.EncodeAddress(), "requested_by": "dave"})
	if resp.StatusCode != 201 {
		t.Fatalf("submit %d %v", resp.StatusCode, wd)
	}
	id := wd["id"].(string)
	src, _ := w.Address(hdwallet.Path{})
	script, _ := txscript.PayToAddrScript(src)
	signBody := map[string]any{"utxos": []map[string]any{{"txid": "00000000000000000000000000000000000000000000000000000000000000ab", "vout": 1, "amount_sats": 100000, "script_pubkey": hex.EncodeToString(script), "address_index": 0}}}

	if resp, _ := post("/withdrawals/"+id+"/sign", signBody); resp.StatusCode != 409 {
		t.Fatalf("signing before approval must fail, got %d", resp.StatusCode)
	}
	full, _ := eng.Get(id)
	msg := policy.ApprovalMessage(full)
	for id2, k := range map[string]ed25519.PrivateKey{"a": privA, "b": privB} {
		if resp, out := post("/withdrawals/"+id+"/approvals", map[string]any{"approver_id": id2, "signature_hex": hex.EncodeToString(ed25519.Sign(k, msg))}); resp.StatusCode != 200 {
			t.Fatalf("approve %s: %d %v", id2, resp.StatusCode, out)
		}
	}
	resp, out := post("/withdrawals/"+id+"/sign", signBody)
	if resp.StatusCode != 200 || out["raw_tx"] == "" || out["broadcast"] != false {
		t.Fatalf("sign %d %v", resp.StatusCode, out)
	}
	if resp, _ := post("/withdrawals/"+id+"/sign", signBody); resp.StatusCode != 409 {
		t.Fatal("second signing must fail")
	}
}
