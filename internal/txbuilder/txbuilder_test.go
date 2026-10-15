package txbuilder_test

import (
	"errors"
	"testing"

	"github.com/applycoding/crypto-custody-signer/internal/hdwallet"
	"github.com/applycoding/crypto-custody-signer/internal/signer"
	"github.com/applycoding/crypto-custody-signer/internal/txbuilder"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
)

const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

func TestBuildAndSignTestnet(t *testing.T) {
	w, _ := hdwallet.FromMnemonic(mnemonic, "", &chaincfg.TestNet3Params)
	b, err := txbuilder.New(w)
	if err != nil {
		t.Fatal(err)
	}
	path := hdwallet.Path{}
	addr, _ := w.Address(path)
	script, _ := txscript.PayToAddrScript(addr)
	hsm := signer.NewMemoryHSM()
	if _, err := txbuilder.ImportPathKey(hsm, w, path); err != nil {
		t.Fatal(err)
	}
	change := hdwallet.Path{Change: 1, Index: 0}
	if _, err := txbuilder.ImportPathKey(hsm, w, change); err != nil {
		t.Fatal(err)
	}
	dest, _ := w.Address(hdwallet.Path{Index: 5})
	txid, _ := chainhash.NewHashFromStr("0000000000000000000000000000000000000000000000000000000000000001")
	tx, digests, err := b.BuildUnsigned(txbuilder.Request{
		UTXOs:       []txbuilder.UTXO{{TxHash: txid, Vout: 0, Amount: 100_000, ScriptPub: script, Path: path}},
		Destination: dest.EncodeAddress(),
		AmountSats:  40_000,
		ChangePath:  change,
		FeeRate:     10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(tx.TxOut) != 2 {
		t.Fatalf("expected dest + change, got %d", len(tx.TxOut))
	}
	if err := b.SignWithBackend(tx, digests, []txbuilder.UTXO{{TxHash: txid, Vout: 0, Amount: 100_000, ScriptPub: script, Path: path}}, hsm); err != nil {
		t.Fatal(err)
	}
	hex, err := txbuilder.Serialize(tx)
	if err != nil || len(hex) < 100 {
		t.Fatalf("serialize: %v %s", err, hex)
	}
}

func TestMainnetRejected(t *testing.T) {
	// fromSeed is package private, so craft a wallet via mnemonic then try New with a mainnet
	// wallet by using the internal fromSeed path through Derive on TestNet and then New.
	// Simpler: FromMnemonic already refuses mainnet; New checks the wallet's params.
	if _, err := hdwallet.FromMnemonic(mnemonic, "", &chaincfg.MainNetParams); !errors.Is(err, hdwallet.ErrMainnet) {
		t.Fatalf("got %v", err)
	}
}

func TestMainnetDestinationRejected(t *testing.T) {
	w, _ := hdwallet.FromMnemonic(mnemonic, "", &chaincfg.TestNet3Params)
	b, _ := txbuilder.New(w)
	txid, _ := chainhash.NewHashFromStr("0000000000000000000000000000000000000000000000000000000000000001")
	addr, _ := w.Address(hdwallet.Path{})
	script, _ := txscript.PayToAddrScript(addr)
	_, _, err := b.BuildUnsigned(txbuilder.Request{
		UTXOs:       []txbuilder.UTXO{{TxHash: txid, Vout: 0, Amount: 100_000, ScriptPub: script}},
		Destination: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", // genesis mainnet address
		AmountSats:  10_000,
	})
	if err == nil {
		t.Fatal("mainnet destination accepted on testnet builder")
	}
}

func TestInsufficientFunds(t *testing.T) {
	w, _ := hdwallet.FromMnemonic(mnemonic, "", &chaincfg.TestNet3Params)
	b, _ := txbuilder.New(w)
	txid, _ := chainhash.NewHashFromStr("0000000000000000000000000000000000000000000000000000000000000001")
	addr, _ := w.Address(hdwallet.Path{})
	script, _ := txscript.PayToAddrScript(addr)
	_, _, err := b.BuildUnsigned(txbuilder.Request{
		UTXOs:       []txbuilder.UTXO{{TxHash: txid, Vout: 0, Amount: 1000, ScriptPub: script}},
		Destination: addr.EncodeAddress(),
		AmountSats:  50_000,
	})
	if err == nil {
		t.Fatal("underfunded spend accepted")
	}
}
