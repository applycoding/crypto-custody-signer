// Package txbuilder builds and signs Bitcoin P2PKH spends on test networks only.
//
// It refuses mainnet parameters, so a misconfiguration cannot create a transaction that
// spends real funds. Fee rate is conservative; UTXOs are supplied by the caller (this demo
// does not talk to a node).
package txbuilder

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/applycoding/crypto-custody-signer/internal/hdwallet"
	"github.com/applycoding/crypto-custody-signer/internal/signer"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// ErrMainnet is returned when mainnet params are supplied.
var ErrMainnet = errors.New("mainnet is disabled; use testnet3 or regtest")

// UTXO is a previous P2PKH output we can spend.
type UTXO struct {
	TxHash    *chainhash.Hash
	Vout      uint32
	Amount    int64
	ScriptPub []byte
	Path      hdwallet.Path // which HD child holds the key
}

// Request is a withdrawal to build.
type Request struct {
	UTXOs       []UTXO
	Destination string
	AmountSats  int64
	ChangePath  hdwallet.Path
	FeeRate     int64 // sat/vB; default 10
}

// Builder holds network params and a wallet for address derivation.
type Builder struct {
	params *chaincfg.Params
	wallet *hdwallet.Wallet
}

func New(wallet *hdwallet.Wallet) (*Builder, error) {
	p := wallet.Params()
	if p.Net == chaincfg.MainNetParams.Net {
		return nil, ErrMainnet
	}
	return &Builder{params: p, wallet: wallet}, nil
}

// BuildUnsigned constructs a P2PKH spend with a change output. It returns the unsigned
// transaction and the sighash digests (one per input) that the HSM must sign.
func (b *Builder) BuildUnsigned(req Request) (*wire.MsgTx, [][]byte, error) {
	if req.AmountSats <= 0 {
		return nil, nil, errors.New("amount must be positive")
	}
	if len(req.UTXOs) == 0 {
		return nil, nil, errors.New("no UTXOs")
	}
	dest, err := btcutil.DecodeAddress(req.Destination, b.params)
	if err != nil {
		return nil, nil, fmt.Errorf("destination: %w", err)
	}
	// Refuse destinations that decode on another network (e.g. a mainnet address).
	if !dest.IsForNet(b.params) {
		return nil, nil, errors.New("destination is not for the configured test network")
	}
	pkScript, err := txscript.PayToAddrScript(dest)
	if err != nil {
		return nil, nil, err
	}
	feeRate := req.FeeRate
	if feeRate <= 0 {
		feeRate = 10
	}
	var inSum int64
	for _, u := range req.UTXOs {
		inSum += u.Amount
	}
	// Rough size: 10 + 148*inputs + 34*2 (destination + change). Recalculated after.
	vbytes := int64(10 + 148*len(req.UTXOs) + 68)
	fee := feeRate * vbytes
	change := inSum - req.AmountSats - fee
	if change < 0 {
		return nil, nil, fmt.Errorf("insufficient funds: need %d have %d", req.AmountSats+fee, inSum)
	}

	tx := wire.NewMsgTx(wire.TxVersion)
	for _, u := range req.UTXOs {
		tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(u.TxHash, u.Vout), nil, nil))
	}
	tx.AddTxOut(wire.NewTxOut(req.AmountSats, pkScript))
	if change >= 546 { // dust threshold
		chAddr, err := b.wallet.Address(req.ChangePath)
		if err != nil {
			return nil, nil, err
		}
		chScript, err := txscript.PayToAddrScript(chAddr)
		if err != nil {
			return nil, nil, err
		}
		tx.AddTxOut(wire.NewTxOut(change, chScript))
	}

	digests := make([][]byte, len(req.UTXOs))
	for i, u := range req.UTXOs {
		digests[i], err = txscript.CalcSignatureHash(u.ScriptPub, txscript.SigHashAll, tx, i)
		if err != nil {
			return nil, nil, err
		}
	}
	return tx, digests, nil
}

// SignWithBackend signs each input with the HSM under label "m/44'/1'/<account>'/<change>/<index>".
func (b *Builder) SignWithBackend(tx *wire.MsgTx, digests [][]byte, utxos []UTXO, backend signer.Backend) error {
	if len(digests) != len(utxos) || len(digests) != len(tx.TxIn) {
		return errors.New("digest/utxo/input length mismatch")
	}
	for i, u := range utxos {
		label := u.Path.String()
		der, err := backend.SignDigest(label, digests[i])
		if err != nil {
			return fmt.Errorf("sign input %d: %w", i, err)
		}
		pub, err := backend.PublicKey(label)
		if err != nil {
			return err
		}
		sigWithType := append(der, byte(txscript.SigHashAll))
		builder := txscript.NewScriptBuilder().AddData(sigWithType).AddData(pub.SerializeCompressed())
		tx.TxIn[i].SignatureScript, err = builder.Script()
		if err != nil {
			return err
		}
		// Engine check: the script must execute successfully against the previous output.
		vm, err := txscript.NewEngine(u.ScriptPub, tx, i, txscript.StandardVerifyFlags, nil, nil, u.Amount, nil)
		if err != nil {
			return err
		}
		if err := vm.Execute(); err != nil {
			return fmt.Errorf("script engine rejected input %d: %w", i, err)
		}
	}
	return nil
}

// Serialize returns the hex of a signed transaction.
func Serialize(tx *wire.MsgTx) (string, error) {
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", buf.Bytes()), nil
}

// ImportPathKey imports the HD child at path into the HSM under its BIP44 path label.
func ImportPathKey(backend signer.Backend, wallet *hdwallet.Wallet, path hdwallet.Path) (*btcec.PublicKey, error) {
	priv, err := wallet.PrivKey(path)
	if err != nil {
		return nil, err
	}
	if err := backend.ImportKey(path.String(), priv); err != nil {
		return nil, err
	}
	return priv.PubKey(), nil
}
