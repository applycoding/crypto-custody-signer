// Package hdwallet derives BIP44 keys from a BIP39 mnemonic using BIP32.
//
// Only Bitcoin testnet and regtest are accepted: the custody demo refuses mainnet parameters
// so it can never produce a key or address that holds real funds by accident.
package hdwallet

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/tyler-smith/go-bip39"
)

// ErrMainnet is returned when mainnet parameters are supplied.
var ErrMainnet = errors.New("mainnet is disabled in this demo; use testnet3 or regtest")

// Purpose and coin type for BIP44 on any test network (SLIP-44 coin type 1).
const (
	Purpose      = 44
	CoinTypeTest = 1
)

// Wallet is an HD wallet rooted at a BIP39 seed.
type Wallet struct {
	master *hdkeychain.ExtendedKey
	params *chaincfg.Params
}

// NewMnemonic returns a fresh 24 word BIP39 mnemonic (256 bits of entropy).
func NewMnemonic() (string, error) {
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return "", err
	}
	return bip39.NewMnemonic(entropy)
}

// SeedFromMnemonic validates the mnemonic checksum and returns the 64 byte BIP39 seed.
func SeedFromMnemonic(mnemonic, passphrase string) ([]byte, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, errors.New("invalid BIP39 mnemonic")
	}
	return bip39.NewSeed(mnemonic, passphrase), nil
}

// FromSeed builds a wallet. Mainnet parameters are rejected unless allowMainnetForVectors is
// set, which only the BIP32 test vector tests do.
func FromSeed(seed []byte, params *chaincfg.Params) (*Wallet, error) {
	if params.Net == chaincfg.MainNetParams.Net {
		return nil, ErrMainnet
	}
	return fromSeed(seed, params)
}

func fromSeed(seed []byte, params *chaincfg.Params) (*Wallet, error) {
	m, err := hdkeychain.NewMaster(seed, params)
	if err != nil {
		return nil, err
	}
	return &Wallet{master: m, params: params}, nil
}

// FromMnemonic is SeedFromMnemonic + FromSeed.
func FromMnemonic(mnemonic, passphrase string, params *chaincfg.Params) (*Wallet, error) {
	seed, err := SeedFromMnemonic(mnemonic, passphrase)
	if err != nil {
		return nil, err
	}
	return FromSeed(seed, params)
}

// Path is a BIP44 path m / 44' / coin' / account' / change / index.
type Path struct {
	Account uint32
	Change  uint32 // 0 external (receive), 1 internal (change)
	Index   uint32
}

func (p Path) String() string {
	return fmt.Sprintf("m/%d'/%d'/%d'/%d/%d", Purpose, CoinTypeTest, p.Account, p.Change, p.Index)
}

// Derive walks a list of child indexes; values >= HardenedKeyStart are hardened.
func Derive(k *hdkeychain.ExtendedKey, path ...uint32) (*hdkeychain.ExtendedKey, error) {
	var err error
	for _, i := range path {
		if k, err = k.Derive(i); err != nil {
			return nil, err
		}
	}
	return k, nil
}

// Key derives the BIP44 child key for a path.
func (w *Wallet) Key(p Path) (*hdkeychain.ExtendedKey, error) {
	if p.Change > 1 {
		return nil, errors.New("change must be 0 or 1")
	}
	h := uint32(hdkeychain.HardenedKeyStart)
	return Derive(w.master, h+Purpose, h+CoinTypeTest, h+p.Account, p.Change, p.Index)
}

// AccountXpub returns the account level extended public key (watch only export).
func (w *Wallet) AccountXpub(account uint32) (string, error) {
	h := uint32(hdkeychain.HardenedKeyStart)
	k, err := Derive(w.master, h+Purpose, h+CoinTypeTest, h+account)
	if err != nil {
		return "", err
	}
	pub, err := k.Neuter()
	if err != nil {
		return "", err
	}
	return pub.String(), nil
}

// PrivKey returns the secp256k1 private key at a path.
func (w *Wallet) PrivKey(p Path) (*btcec.PrivateKey, error) {
	k, err := w.Key(p)
	if err != nil {
		return nil, err
	}
	return k.ECPrivKey()
}

// Address returns the P2PKH address at a path (BIP44 uses legacy P2PKH).
func (w *Wallet) Address(p Path) (*btcutil.AddressPubKeyHash, error) {
	k, err := w.Key(p)
	if err != nil {
		return nil, err
	}
	return k.Address(w.params)
}

// Params exposes the network parameters.
func (w *Wallet) Params() *chaincfg.Params { return w.params }
