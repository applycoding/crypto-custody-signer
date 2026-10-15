// Package api wires the policy engine, attestor, HSM backend and tx builder behind HTTP.
package api

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/applycoding/crypto-custody-signer/internal/attest"
	"github.com/applycoding/crypto-custody-signer/internal/hdwallet"
	"github.com/applycoding/crypto-custody-signer/internal/policy"
	"github.com/applycoding/crypto-custody-signer/internal/signer"
	"github.com/applycoding/crypto-custody-signer/internal/txbuilder"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

// Service is the custody flow: submit -> approve (m of n, ed25519) -> attest (Vault) -> sign (HSM).
type Service struct {
	Engine   *policy.Engine
	Attestor attest.Attestor
	HSM      signer.Backend
	Builder  *txbuilder.Builder
	Wallet   *hdwallet.Wallet
}

// SignRequest carries the UTXOs to spend (this demo does not query a node).
type SignRequest struct {
	UTXOs []struct {
		TxID       string `json:"txid"`
		Vout       uint32 `json:"vout"`
		AmountSats int64  `json:"amount_sats"`
		ScriptHex  string `json:"script_pubkey"`
		Index      uint32 `json:"address_index"`
	} `json:"utxos"`
	FeeRate int64 `json:"fee_rate"`
}

// Sign authorizes against policy, gets an attestation, verifies it and signs the transaction.
func (s *Service) Sign(id string, req SignRequest) (map[string]any, error) {
	w, err := s.Engine.AuthorizeSigning(id)
	if err != nil {
		return nil, err
	}
	decision, _ := json.Marshal(map[string]any{"withdrawal": w.ID, "amount_sats": w.AmountSats, "destination": w.Destination, "status": w.Status})
	att, err := s.Attestor.Sign(decision)
	if err != nil {
		return nil, err
	}
	// The signing step independently verifies the attestation before touching the HSM.
	if ok, err := s.Attestor.Verify(decision, att); err != nil || !ok {
		return nil, errors.New("policy attestation failed verification")
	}
	var utxos []txbuilder.UTXO
	for _, u := range req.UTXOs {
		h, err := chainhash.NewHashFromStr(u.TxID)
		if err != nil {
			return nil, err
		}
		script, err := hex.DecodeString(u.ScriptHex)
		if err != nil {
			return nil, err
		}
		utxos = append(utxos, txbuilder.UTXO{TxHash: h, Vout: u.Vout, Amount: u.AmountSats, ScriptPub: script, Path: hdwallet.Path{Index: u.Index}})
	}
	tx, digests, err := s.Builder.BuildUnsigned(txbuilder.Request{UTXOs: utxos, Destination: w.Destination, AmountSats: w.AmountSats, ChangePath: hdwallet.Path{Change: 1}, FeeRate: req.FeeRate})
	if err != nil {
		return nil, err
	}
	if err := s.Builder.SignWithBackend(tx, digests, utxos, s.HSM); err != nil {
		return nil, err
	}
	raw, _ := txbuilder.Serialize(tx)
	return map[string]any{"withdrawal": w, "attestation": att, "txid": tx.TxHash().String(), "raw_tx": raw, "broadcast": false}, nil
}

// Handler exposes the service over HTTP.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) { write(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /addresses/{index}", func(w http.ResponseWriter, r *http.Request) {
		var idx uint32
		if err := json.Unmarshal([]byte(r.PathValue("index")), &idx); err != nil {
			write(w, 400, errBody(err))
			return
		}
		a, err := s.Wallet.Address(hdwallet.Path{Index: idx})
		if err != nil {
			write(w, 400, errBody(err))
			return
		}
		write(w, 200, map[string]any{"path": hdwallet.Path{Index: idx}.String(), "address": a.EncodeAddress()})
	})
	mux.HandleFunc("POST /withdrawals", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			AmountSats  int64  `json:"amount_sats"`
			Destination string `json:"destination"`
			RequestedBy string `json:"requested_by"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			write(w, 400, errBody(err))
			return
		}
		wd, err := s.Engine.Submit("tBTC", in.AmountSats, in.Destination, in.RequestedBy)
		respond(w, 201, wd, err)
	})
	mux.HandleFunc("GET /withdrawals/{id}", func(w http.ResponseWriter, r *http.Request) {
		wd, err := s.Engine.Get(r.PathValue("id"))
		respond(w, 200, wd, err)
	})
	mux.HandleFunc("GET /withdrawals/{id}/message", func(w http.ResponseWriter, r *http.Request) {
		wd, err := s.Engine.Get(r.PathValue("id"))
		if err != nil {
			respond(w, 0, nil, err)
			return
		}
		write(w, 200, map[string]string{"message": string(policy.ApprovalMessage(wd))})
	})
	mux.HandleFunc("POST /withdrawals/{id}/approvals", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			ApproverID   string `json:"approver_id"`
			SignatureHex string `json:"signature_hex"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			write(w, 400, errBody(err))
			return
		}
		sig, err := hex.DecodeString(in.SignatureHex)
		if err != nil {
			write(w, 400, errBody(err))
			return
		}
		wd, err := s.Engine.Approve(r.PathValue("id"), in.ApproverID, sig)
		respond(w, 200, wd, err)
	})
	mux.HandleFunc("POST /withdrawals/{id}/sign", func(w http.ResponseWriter, r *http.Request) {
		var in SignRequest
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			write(w, 400, errBody(err))
			return
		}
		out, err := s.Sign(r.PathValue("id"), in)
		respond(w, 200, out, err)
	})
	return mux
}

func respond(w http.ResponseWriter, ok int, body any, err error) {
	switch {
	case err == nil:
		write(w, ok, body)
	case errors.Is(err, policy.ErrNotFound):
		write(w, 404, errBody(err))
	case errors.Is(err, policy.ErrBadSignature), errors.Is(err, policy.ErrSelfApproval), errors.Is(err, policy.ErrUnknownSigner):
		write(w, 403, errBody(err))
	case errors.Is(err, policy.ErrNotApproved), errors.Is(err, policy.ErrNotPending), errors.Is(err, policy.ErrDuplicate):
		write(w, 409, errBody(err))
	default:
		write(w, 422, errBody(err))
	}
}

func errBody(err error) map[string]string {
	return map[string]string{"error": strings.TrimSpace(err.Error())}
}

func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
