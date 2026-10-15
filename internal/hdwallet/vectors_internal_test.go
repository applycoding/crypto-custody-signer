package hdwallet

import (
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
)

// BIP32 test vector 1 (https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki).
func TestBIP32Vector1(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	w, err := fromSeed(seed, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatal(err)
	}
	if got := w.master.String(); got != "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi" {
		t.Fatalf("master xprv mismatch: %s", got)
	}
	h := uint32(hdkeychain.HardenedKeyStart)
	k, err := Derive(w.master, h+0, 1, h+2)
	if err != nil {
		t.Fatal(err)
	}
	if got := k.String(); got != "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM" {
		t.Fatalf("m/0'/1/2' xprv mismatch: %s", got)
	}
}

// BIP44 mainnet address for the well known "abandon ... about" mnemonic, to prove the
// derivation path logic matches other wallets. Mainnet is only reachable from this test.
func TestBIP44KnownAddressMainnet(t *testing.T) {
	seed, err := SeedFromMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "")
	if err != nil {
		t.Fatal(err)
	}
	w, _ := fromSeed(seed, &chaincfg.MainNetParams)
	h := uint32(hdkeychain.HardenedKeyStart)
	k, _ := Derive(w.master, h+44, h+0, h+0, 0, 0)
	addr, _ := k.Address(&chaincfg.MainNetParams)
	if addr.EncodeAddress() != "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA" {
		t.Fatalf("got %s", addr.EncodeAddress())
	}
}
