package hdwallet_test

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/applycoding/crypto-custody-signer/internal/hdwallet"
	"github.com/btcsuite/btcd/chaincfg"
)

const abandon = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

// BIP39 reference vector (Trezor python-mnemonic vectors.json, passphrase "TREZOR").
func TestBIP39Seed(t *testing.T) {
	seed, err := hdwallet.SeedFromMnemonic(abandon, "TREZOR")
	if err != nil {
		t.Fatal(err)
	}
	want := "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
	if hex.EncodeToString(seed) != want {
		t.Fatalf("seed mismatch")
	}
}

func TestInvalidMnemonicRejected(t *testing.T) {
	if _, err := hdwallet.SeedFromMnemonic(strings.Replace(abandon, "about", "abandon", 1), ""); err == nil {
		t.Fatal("bad checksum accepted")
	}
}

func TestMainnetRefused(t *testing.T) {
	if _, err := hdwallet.FromMnemonic(abandon, "", &chaincfg.MainNetParams); !errors.Is(err, hdwallet.ErrMainnet) {
		t.Fatalf("expected ErrMainnet, got %v", err)
	}
}

func TestTestnetBIP44Address(t *testing.T) {
	w, err := hdwallet.FromMnemonic(abandon, "", &chaincfg.TestNet3Params)
	if err != nil {
		t.Fatal(err)
	}
	a, err := w.Address(hdwallet.Path{})
	if err != nil {
		t.Fatal(err)
	}
	if a.EncodeAddress() != "mkpZhYtJu2r87Js3pDiWJDmPte2NRZ8bJV" {
		t.Fatalf("got %s", a.EncodeAddress())
	}
	if (hdwallet.Path{Account: 0, Change: 1, Index: 3}).String() != "m/44'/1'/0'/1/3" {
		t.Fatal("path formatting")
	}
}

func TestAddressesDistinctAndXpubIsPublic(t *testing.T) {
	w, _ := hdwallet.FromMnemonic(abandon, "", &chaincfg.TestNet3Params)
	seen := map[string]bool{}
	for i := uint32(0); i < 20; i++ {
		a, _ := w.Address(hdwallet.Path{Index: i})
		if seen[a.EncodeAddress()] {
			t.Fatal("duplicate address")
		}
		seen[a.EncodeAddress()] = true
	}
	x, err := w.AccountXpub(0)
	if err != nil || !strings.HasPrefix(x, "tpub") {
		t.Fatalf("xpub %q err %v", x, err)
	}
	if _, err := w.Key(hdwallet.Path{Change: 2}); err == nil {
		t.Fatal("change > 1 accepted")
	}
}

func TestNewMnemonic(t *testing.T) {
	m, err := hdwallet.NewMnemonic()
	if err != nil || len(strings.Fields(m)) != 24 {
		t.Fatalf("mnemonic %q err %v", m, err)
	}
}
