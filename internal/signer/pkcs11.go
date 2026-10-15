//go:build pkcs11

package signer

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/miekg/pkcs11"
)

// DER encoded OID 1.3.132.0.10 (secp256k1), used as CKA_EC_PARAMS.
var secp256k1Params = []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a}

// PKCS11 is a Backend over a PKCS#11 token (SoftHSM2 in CI, a network HSM in principle).
type PKCS11 struct {
	mu      sync.Mutex
	ctx     *pkcs11.Ctx
	session pkcs11.SessionHandle
}

// OpenPKCS11 loads the module, finds the token by label and logs in as user.
func OpenPKCS11(modulePath, tokenLabel, pin string) (*PKCS11, error) {
	ctx := pkcs11.New(modulePath)
	if ctx == nil {
		return nil, fmt.Errorf("cannot load PKCS#11 module %s", modulePath)
	}
	if err := ctx.Initialize(); err != nil {
		return nil, err
	}
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return nil, err
	}
	for _, s := range slots {
		info, err := ctx.GetTokenInfo(s)
		if err != nil || info.Label != tokenLabel {
			continue
		}
		sess, err := ctx.OpenSession(s, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err != nil {
			return nil, err
		}
		if err := ctx.Login(sess, pkcs11.CKU_USER, pin); err != nil {
			return nil, err
		}
		return &PKCS11{ctx: ctx, session: sess}, nil
	}
	return nil, fmt.Errorf("token %q not found", tokenLabel)
}

// Close logs out and finalizes the module.
func (p *PKCS11) Close() {
	p.ctx.Logout(p.session)
	p.ctx.CloseSession(p.session)
	p.ctx.Finalize()
	p.ctx.Destroy()
}

func (p *PKCS11) find(label string, class uint) (pkcs11.ObjectHandle, error) {
	tmpl := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_CLASS, class), pkcs11.NewAttribute(pkcs11.CKA_LABEL, label)}
	if err := p.ctx.FindObjectsInit(p.session, tmpl); err != nil {
		return 0, err
	}
	defer p.ctx.FindObjectsFinal(p.session)
	objs, _, err := p.ctx.FindObjects(p.session, 1)
	if err != nil {
		return 0, err
	}
	if len(objs) == 0 {
		return 0, fmt.Errorf("%w: %s", ErrNoKey, label)
	}
	return objs[0], nil
}

// ImportKey creates a non extractable private key object and the matching public key object.
func (p *PKCS11) ImportKey(label string, key *btcec.PrivateKey) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, err := p.find(label, pkcs11.CKO_PRIVATE_KEY); err == nil {
		return fmt.Errorf("key %s already exists", label)
	}
	point, err := asn1.Marshal(key.PubKey().SerializeUncompressed())
	if err != nil {
		return err
	}
	priv := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, secp256k1Params),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, key.Serialize()),
	}
	pub := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, secp256k1Params),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, point),
	}
	if _, err := p.ctx.CreateObject(p.session, priv); err != nil {
		return fmt.Errorf("create private key: %w", err)
	}
	if _, err := p.ctx.CreateObject(p.session, pub); err != nil {
		return fmt.Errorf("create public key: %w", err)
	}
	return nil
}

// GenerateKey creates a key pair inside the token (the private key never leaves it).
func (p *PKCS11) GenerateKey(label string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	pub := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, secp256k1Params),
	}
	priv := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}
	_, _, err := p.ctx.GenerateKeyPair(p.session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)}, pub, priv)
	return err
}

// SignDigest signs with CKM_ECDSA (raw digest in, r||s out) and returns low S DER.
func (p *PKCS11) SignDigest(label string, digest []byte) ([]byte, error) {
	if len(digest) != 32 {
		return nil, errors.New("digest must be 32 bytes")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	h, err := p.find(label, pkcs11.CKO_PRIVATE_KEY)
	if err != nil {
		return nil, err
	}
	if err := p.ctx.SignInit(p.session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}, h); err != nil {
		return nil, err
	}
	raw, err := p.ctx.Sign(p.session, digest)
	if err != nil {
		return nil, err
	}
	return RawToLowSDER(raw)
}

// PublicKey reads CKA_EC_POINT (a DER OCTET STRING around the uncompressed point).
func (p *PKCS11) PublicKey(label string) (*btcec.PublicKey, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	h, err := p.find(label, pkcs11.CKO_PUBLIC_KEY)
	if err != nil {
		return nil, err
	}
	attrs, err := p.ctx.GetAttributeValue(p.session, h, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil)})
	if err != nil {
		return nil, err
	}
	var point []byte
	if _, err := asn1.Unmarshal(attrs[0].Value, &point); err != nil {
		return nil, err
	}
	return btcec.ParsePubKey(point)
}
