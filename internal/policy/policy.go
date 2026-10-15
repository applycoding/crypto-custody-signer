// Package policy is a multi approval policy engine for withdrawals.
//
// A withdrawal moves through: pending -> approved -> signed, or pending -> rejected/expired.
// Rules are evaluated on every approval and again just before signing (defence in depth).
package policy

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Status of a withdrawal request.
type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusRejected Status = "rejected"
	StatusSigned   Status = "signed"
	StatusExpired  Status = "expired"
)

// Approver is a person who can approve withdrawals with their ed25519 key.
type Approver struct {
	ID        string            `json:"id"`
	Roles     []string          `json:"roles"`
	PublicKey ed25519.PublicKey `json:"public_key"`
}

func (a Approver) has(role string) bool {
	for _, r := range a.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// Tier sets how many approvals (and which roles) an amount needs. Tiers are matched by the
// highest MinAmount that is <= the requested amount.
type Tier struct {
	MinAmount     int64    `json:"min_amount_sats"`
	Approvals     int      `json:"approvals"`
	RequiredRoles []string `json:"required_roles"`
}

// Rules is the full policy.
type Rules struct {
	Tiers              []Tier          `json:"tiers"`
	AllowedDestination map[string]bool `json:"allowed_destinations"` // empty map means any address
	DailyLimit         int64           `json:"daily_limit_sats"`
	ApprovalTTL        time.Duration   `json:"approval_ttl"`
	RequestTTL         time.Duration   `json:"request_ttl"`
}

// Withdrawal is a request to send funds.
type Withdrawal struct {
	ID          string              `json:"id"`
	Asset       string              `json:"asset"`
	AmountSats  int64               `json:"amount_sats"`
	Destination string              `json:"destination"`
	RequestedBy string              `json:"requested_by"`
	CreatedAt   time.Time           `json:"created_at"`
	Status      Status              `json:"status"`
	Approvals   map[string]Approval `json:"approvals"`
	Reason      string              `json:"reason,omitempty"`
}

// Approval is a signed vote.
type Approval struct {
	ApproverID string    `json:"approver_id"`
	At         time.Time `json:"at"`
	Signature  []byte    `json:"signature"`
}

// Errors returned by the engine.
var (
	ErrNotFound       = errors.New("withdrawal not found")
	ErrSelfApproval   = errors.New("requester cannot approve their own withdrawal")
	ErrBadSignature   = errors.New("approval signature does not verify")
	ErrUnknownSigner  = errors.New("unknown approver")
	ErrDuplicate      = errors.New("approver already approved")
	ErrNotPending     = errors.New("withdrawal is not pending")
	ErrDestination    = errors.New("destination is not on the allowlist")
	ErrDailyLimit     = errors.New("daily limit exceeded")
	ErrNotApproved    = errors.New("withdrawal does not satisfy policy")
	ErrInvalidRequest = errors.New("invalid withdrawal request")
)

// ApprovalMessage is the canonical byte string an approver signs. Binding every field stops a
// signature for one withdrawal being replayed on another.
func ApprovalMessage(w *Withdrawal) []byte {
	b, _ := json.Marshal(struct {
		Domain      string `json:"domain"`
		ID          string `json:"id"`
		Asset       string `json:"asset"`
		Amount      int64  `json:"amount_sats"`
		Destination string `json:"destination"`
	}{"custody-approval-v1", w.ID, w.Asset, w.AmountSats, w.Destination})
	return b
}

// Engine stores requests in memory and enforces Rules.
type Engine struct {
	mu        sync.Mutex
	rules     Rules
	approvers map[string]Approver
	requests  map[string]*Withdrawal
	now       func() time.Time
	seq       int
}

// NewEngine validates and installs the rules.
func NewEngine(rules Rules, approvers []Approver, now func() time.Time) (*Engine, error) {
	if len(rules.Tiers) == 0 {
		return nil, errors.New("at least one tier required")
	}
	sort.Slice(rules.Tiers, func(i, j int) bool { return rules.Tiers[i].MinAmount < rules.Tiers[j].MinAmount })
	if rules.Tiers[0].MinAmount != 0 {
		return nil, errors.New("first tier must start at 0")
	}
	if now == nil {
		now = time.Now
	}
	m := map[string]Approver{}
	for _, a := range approvers {
		if len(a.PublicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("approver %s has invalid key", a.ID)
		}
		m[a.ID] = a
	}
	return &Engine{rules: rules, approvers: m, requests: map[string]*Withdrawal{}, now: now}, nil
}

// TierFor returns the tier that applies to an amount.
func (e *Engine) TierFor(amount int64) Tier {
	t := e.rules.Tiers[0]
	for _, c := range e.rules.Tiers {
		if amount >= c.MinAmount {
			t = c
		}
	}
	return t
}

// Submit creates a pending withdrawal after static checks (allowlist, daily limit).
func (e *Engine) Submit(asset string, amount int64, destination, requester string) (*Withdrawal, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if amount <= 0 || destination == "" || requester == "" {
		return nil, ErrInvalidRequest
	}
	if len(e.rules.AllowedDestination) > 0 && !e.rules.AllowedDestination[destination] {
		return nil, ErrDestination
	}
	if e.rules.DailyLimit > 0 && e.spentToday()+amount > e.rules.DailyLimit {
		return nil, ErrDailyLimit
	}
	e.seq++
	w := &Withdrawal{ID: fmt.Sprintf("wd_%d", e.seq), Asset: asset, AmountSats: amount, Destination: destination,
		RequestedBy: requester, CreatedAt: e.now(), Status: StatusPending, Approvals: map[string]Approval{}}
	e.requests[w.ID] = w
	return w.clone(), nil
}

// spentToday sums non rejected withdrawals in the trailing 24h (pending ones reserve budget).
func (e *Engine) spentToday() int64 {
	var s int64
	cutoff := e.now().Add(-24 * time.Hour)
	for _, w := range e.requests {
		if w.CreatedAt.After(cutoff) && w.Status != StatusRejected && w.Status != StatusExpired {
			s += w.AmountSats
		}
	}
	return s
}

// Approve records a signed approval and moves the request to approved once policy is met.
func (e *Engine) Approve(id, approverID string, sig []byte) (*Withdrawal, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	w, ok := e.requests[id]
	if !ok {
		return nil, ErrNotFound
	}
	e.expire(w)
	if w.Status != StatusPending {
		return nil, ErrNotPending
	}
	a, ok := e.approvers[approverID]
	if !ok {
		return nil, ErrUnknownSigner
	}
	if approverID == w.RequestedBy {
		return nil, ErrSelfApproval
	}
	if _, dup := w.Approvals[approverID]; dup {
		return nil, ErrDuplicate
	}
	if !ed25519.Verify(a.PublicKey, ApprovalMessage(w), sig) {
		return nil, ErrBadSignature
	}
	w.Approvals[approverID] = Approval{ApproverID: approverID, At: e.now(), Signature: sig}
	if e.satisfied(w) == nil {
		w.Status = StatusApproved
	}
	return w.clone(), nil
}

// Reject moves a pending request to rejected. Any approver can veto.
func (e *Engine) Reject(id, approverID, reason string) (*Withdrawal, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	w, ok := e.requests[id]
	if !ok {
		return nil, ErrNotFound
	}
	if _, ok := e.approvers[approverID]; !ok {
		return nil, ErrUnknownSigner
	}
	if w.Status != StatusPending && w.Status != StatusApproved {
		return nil, ErrNotPending
	}
	w.Status, w.Reason = StatusRejected, reason
	return w.clone(), nil
}

// satisfied checks quorum and roles using only approvals that are still fresh.
func (e *Engine) satisfied(w *Withdrawal) error {
	tier := e.TierFor(w.AmountSats)
	fresh := 0
	roles := map[string]bool{}
	for id, ap := range w.Approvals {
		if e.rules.ApprovalTTL > 0 && e.now().Sub(ap.At) > e.rules.ApprovalTTL {
			continue
		}
		fresh++
		for _, r := range e.approvers[id].Roles {
			roles[r] = true
		}
	}
	if fresh < tier.Approvals {
		return fmt.Errorf("%w: %d of %d approvals", ErrNotApproved, fresh, tier.Approvals)
	}
	for _, r := range tier.RequiredRoles {
		if !roles[r] {
			return fmt.Errorf("%w: missing role %s", ErrNotApproved, r)
		}
	}
	return nil
}

func (e *Engine) expire(w *Withdrawal) {
	if w.Status == StatusPending && e.rules.RequestTTL > 0 && e.now().Sub(w.CreatedAt) > e.rules.RequestTTL {
		w.Status, w.Reason = StatusExpired, "request ttl elapsed"
	}
}

// AuthorizeSigning re-checks the policy and marks the request signed. The caller must only
// sign the transaction if this returns nil. It is single use: a second call fails.
func (e *Engine) AuthorizeSigning(id string) (*Withdrawal, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	w, ok := e.requests[id]
	if !ok {
		return nil, ErrNotFound
	}
	if w.Status != StatusApproved {
		return nil, fmt.Errorf("%w: status is %s", ErrNotApproved, w.Status)
	}
	if err := e.satisfied(w); err != nil {
		return nil, err
	}
	w.Status = StatusSigned
	return w.clone(), nil
}

// Get returns a copy of a request.
func (e *Engine) Get(id string) (*Withdrawal, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	w, ok := e.requests[id]
	if !ok {
		return nil, ErrNotFound
	}
	e.expire(w)
	return w.clone(), nil
}

func (w *Withdrawal) clone() *Withdrawal {
	c := *w
	c.Approvals = make(map[string]Approval, len(w.Approvals))
	for k, v := range w.Approvals {
		c.Approvals[k] = v
	}
	return &c
}
