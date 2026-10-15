// Command custodyd runs the custody signer demo on testnet3 with in memory backends.
//
// Environment: MNEMONIC (defaults to a fresh random one, printed as a warning), APPROVERS_JSON
// (list of {id, roles, public_key_hex}), VAULT_ADDR/VAULT_TOKEN to use Vault transit for
// policy attestations, PORT.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/applycoding/crypto-custody-signer/internal/api"
	"github.com/applycoding/crypto-custody-signer/internal/attest"
	"github.com/applycoding/crypto-custody-signer/internal/hdwallet"
	"github.com/applycoding/crypto-custody-signer/internal/policy"
	"github.com/applycoding/crypto-custody-signer/internal/signer"
	"github.com/applycoding/crypto-custody-signer/internal/txbuilder"
	"github.com/btcsuite/btcd/chaincfg"
)

func main() {
	mnemonic := os.Getenv("MNEMONIC")
	if mnemonic == "" {
		var err error
		if mnemonic, err = hdwallet.NewMnemonic(); err != nil {
			log.Fatal(err)
		}
		log.Println("WARNING: no MNEMONIC set, generated a throwaway testnet wallet")
	}
	w, err := hdwallet.FromMnemonic(mnemonic, "", &chaincfg.TestNet3Params)
	if err != nil {
		log.Fatal(err)
	}
	b, _ := txbuilder.New(w)
	hsm := signer.NewMemoryHSM()
	for i := uint32(0); i < 20; i++ {
		for _, ch := range []uint32{0, 1} {
			if _, err := txbuilder.ImportPathKey(hsm, w, hdwallet.Path{Change: ch, Index: i}); err != nil {
				log.Fatal(err)
			}
		}
	}
	var approvers []policy.Approver
	if raw := os.Getenv("APPROVERS_JSON"); raw != "" {
		var in []struct {
			ID     string   `json:"id"`
			Roles  []string `json:"roles"`
			PubHex string   `json:"public_key_hex"`
		}
		if err := json.Unmarshal([]byte(raw), &in); err != nil {
			log.Fatal(err)
		}
		for _, a := range in {
			pk, _ := hex.DecodeString(a.PubHex)
			approvers = append(approvers, policy.Approver{ID: a.ID, Roles: a.Roles, PublicKey: ed25519.PublicKey(pk)})
		}
	}
	eng, err := policy.NewEngine(policy.Rules{
		Tiers:       []policy.Tier{{MinAmount: 0, Approvals: 1}, {MinAmount: 1_000_000, Approvals: 2}, {MinAmount: 10_000_000, Approvals: 3, RequiredRoles: []string{"risk"}}},
		DailyLimit:  50_000_000,
		ApprovalTTL: time.Hour,
		RequestTTL:  24 * time.Hour,
	}, approvers, nil)
	if err != nil {
		log.Fatal(err)
	}
	var att attest.Attestor = attest.NewLocal()
	if addr := os.Getenv("VAULT_ADDR"); addr != "" {
		v := attest.NewVaultTransit(addr, os.Getenv("VAULT_TOKEN"), "custody-policy")
		if err := v.EnsureKey(); err != nil {
			log.Fatal(err)
		}
		att = v
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("custodyd on :%s (testnet3, %d approvers)", port, len(approvers))
	srv := &http.Server{Addr: ":" + port, Handler: (&api.Service{Engine: eng, Attestor: att, HSM: hsm, Builder: b, Wallet: w}).Handler(), ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
