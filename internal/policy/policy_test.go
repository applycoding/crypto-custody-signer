package policy_test

import (
	"crypto/ed25519"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/applycoding/crypto-custody-signer/internal/policy"
)

type actor struct {
	id   string
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func newActor(id string) actor {
	pub, priv, _ := ed25519.GenerateKey(nil)
	return actor{id, priv, pub}
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func setup(t *testing.T) (*policy.Engine, map[string]actor, *clock) {
	t.Helper()
	acts := map[string]actor{"alice": newActor("alice"), "bob": newActor("bob"), "carol": newActor("carol"), "risk": newActor("risk")}
	roles := map[string][]string{"alice": {"ops"}, "bob": {"ops"}, "carol": {"ops"}, "risk": {"risk"}}
	var approvers []policy.Approver
	for id, a := range acts {
		approvers = append(approvers, policy.Approver{ID: id, Roles: roles[id], PublicKey: a.pub})
	}
	c := &clock{time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	e, err := policy.NewEngine(policy.Rules{
		Tiers: []policy.Tier{
			{MinAmount: 0, Approvals: 1},
			{MinAmount: 1_000_000, Approvals: 2},
			{MinAmount: 10_000_000, Approvals: 3, RequiredRoles: []string{"risk"}},
		},
		DailyLimit:  50_000_000,
		ApprovalTTL: time.Hour,
		RequestTTL:  24 * time.Hour,
	}, approvers, c.now)
	if err != nil {
		t.Fatal(err)
	}
	return e, acts, c
}

func approve(t *testing.T, e *policy.Engine, w *policy.Withdrawal, a actor) (*policy.Withdrawal, error) {
	t.Helper()
	return e.Approve(w.ID, a.id, ed25519.Sign(a.priv, policy.ApprovalMessage(w)))
}

func TestSmallWithdrawalNeedsOneApproval(t *testing.T) {
	e, a, _ := setup(t)
	w, _ := e.Submit("tBTC", 50_000, "tb1qdest", "dave")
	w, err := approve(t, e, w, a["alice"])
	if err != nil || w.Status != policy.StatusApproved {
		t.Fatalf("status %v err %v", w.Status, err)
	}
	if _, err := e.AuthorizeSigning(w.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.AuthorizeSigning(w.ID); err == nil {
		t.Fatal("authorization must be single use")
	}
}

func TestLargeWithdrawalNeedsRiskRole(t *testing.T) {
	e, a, _ := setup(t)
	w, _ := e.Submit("tBTC", 20_000_000, "tb1qdest", "dave")
	for _, id := range []string{"alice", "bob", "carol"} {
		w, _ = approve(t, e, w, a[id])
	}
	if w.Status != policy.StatusPending {
		t.Fatal("3 ops approvals without risk must not approve")
	}
	w, _ = approve(t, e, w, a["risk"])
	if w.Status != policy.StatusApproved {
		t.Fatal("risk approval should complete quorum")
	}
}

func TestSelfApprovalDuplicateAndForgery(t *testing.T) {
	e, a, _ := setup(t)
	w, _ := e.Submit("tBTC", 2_000_000, "tb1qdest", "alice")
	if _, err := approve(t, e, w, a["alice"]); !errors.Is(err, policy.ErrSelfApproval) {
		t.Fatalf("got %v", err)
	}
	if _, err := approve(t, e, w, a["bob"]); err != nil {
		t.Fatal(err)
	}
	if _, err := approve(t, e, w, a["bob"]); !errors.Is(err, policy.ErrDuplicate) {
		t.Fatalf("got %v", err)
	}
	// carol signs with bob's key: must fail.
	forged := ed25519.Sign(a["bob"].priv, policy.ApprovalMessage(w))
	if _, err := e.Approve(w.ID, "carol", forged); !errors.Is(err, policy.ErrBadSignature) {
		t.Fatalf("got %v", err)
	}
	if _, err := e.Approve(w.ID, "mallory", forged); !errors.Is(err, policy.ErrUnknownSigner) {
		t.Fatalf("got %v", err)
	}
}

func TestSignatureNotReplayableAcrossRequests(t *testing.T) {
	e, a, _ := setup(t)
	w1, _ := e.Submit("tBTC", 10_000, "tb1qdest", "dave")
	w2, _ := e.Submit("tBTC", 10_000, "tb1qother", "dave")
	sig := ed25519.Sign(a["bob"].priv, policy.ApprovalMessage(w1))
	if _, err := e.Approve(w2.ID, "bob", sig); !errors.Is(err, policy.ErrBadSignature) {
		t.Fatalf("replay accepted: %v", err)
	}
}

func TestStaleApprovalsDoNotCount(t *testing.T) {
	e, a, c := setup(t)
	w, _ := e.Submit("tBTC", 2_000_000, "tb1qdest", "dave")
	approve(t, e, w, a["alice"])
	c.t = c.t.Add(2 * time.Hour)
	w, _ = approve(t, e, w, a["bob"])
	if w.Status != policy.StatusPending {
		t.Fatal("expired approval counted towards quorum")
	}
}

func TestRequestExpiry(t *testing.T) {
	e, a, c := setup(t)
	w, _ := e.Submit("tBTC", 10_000, "tb1qdest", "dave")
	c.t = c.t.Add(25 * time.Hour)
	if _, err := approve(t, e, w, a["alice"]); !errors.Is(err, policy.ErrNotPending) {
		t.Fatalf("got %v", err)
	}
	got, _ := e.Get(w.ID)
	if got.Status != policy.StatusExpired {
		t.Fatalf("status %s", got.Status)
	}
}

func TestDailyLimitAndAllowlist(t *testing.T) {
	e, _, _ := setup(t)
	if _, err := e.Submit("tBTC", 40_000_000, "x", "dave"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Submit("tBTC", 20_000_000, "x", "dave"); !errors.Is(err, policy.ErrDailyLimit) {
		t.Fatalf("got %v", err)
	}
	e2, _ := policy.NewEngine(policy.Rules{Tiers: []policy.Tier{{Approvals: 1}}, AllowedDestination: map[string]bool{"tb1qok": true}}, nil, nil)
	if _, err := e2.Submit("tBTC", 1, "tb1qbad", "dave"); !errors.Is(err, policy.ErrDestination) {
		t.Fatalf("got %v", err)
	}
	if _, err := e2.Submit("tBTC", 0, "tb1qok", "dave"); !errors.Is(err, policy.ErrInvalidRequest) {
		t.Fatalf("got %v", err)
	}
}

func TestRejectIsFinal(t *testing.T) {
	e, a, _ := setup(t)
	w, _ := e.Submit("tBTC", 10_000, "tb1qdest", "dave")
	if _, err := e.Reject(w.ID, "risk", "suspicious"); err != nil {
		t.Fatal(err)
	}
	if _, err := approve(t, e, w, a["alice"]); !errors.Is(err, policy.ErrNotPending) {
		t.Fatalf("got %v", err)
	}
	if _, err := e.AuthorizeSigning(w.ID); err == nil {
		t.Fatal("rejected request authorized")
	}
}

func TestConcurrentAuthorizeIsSingleUse(t *testing.T) {
	e, a, _ := setup(t)
	w, _ := e.Submit("tBTC", 10_000, "tb1qdest", "dave")
	approve(t, e, w, a["alice"])
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := e.AuthorizeSigning(w.ID); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("authorized %d times", ok)
	}
}
