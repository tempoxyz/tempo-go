package keychain

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

// TIP20 function selectors.
var (
	SelectorTransfer         = [4]byte{0xa9, 0x05, 0x9c, 0xbb} // transfer(address,uint256)
	SelectorApprove          = [4]byte{0x09, 0x5e, 0xa7, 0xb3} // approve(address,uint256)
	SelectorTransferWithMemo = [4]byte{0x44, 0x7b, 0x73, 0x2f} // transferWithMemo(address,uint256,bytes32)
	SelectorWildcard         = [4]byte{0x00, 0x00, 0x00, 0x00}
)

// SelectorRule restricts a single function selector to an optional set of
// first-argument (recipient) addresses. An empty Recipients list means any
// recipient is allowed.
type SelectorRule struct {
	Selector   [4]byte
	Recipients []common.Address
}

// CallScope restricts the calls an access key may make to a single target
// contract, optionally scoped to specific function selectors and recipients.
type CallScope struct {
	Target        common.Address
	SelectorRules []SelectorRule
}

// CallScopeBuilder builds a CallScope with a fluent API.
type CallScopeBuilder struct {
	target        common.Address
	selectorRules []SelectorRule
}

// NewCallScopeBuilder creates a builder for the given target contract.
func NewCallScopeBuilder(target common.Address) *CallScopeBuilder {
	return &CallScopeBuilder{target: target}
}

// WithSelector allows calls matching an arbitrary 4-byte function selector.
func (b *CallScopeBuilder) WithSelector(selector [4]byte) *CallScopeBuilder {
	b.selectorRules = append(b.selectorRules, SelectorRule{
		Selector: selector,
	})
	return b
}

// Transfer allows transfer(address,uint256) calls, optionally restricted to
// the given recipients.
func (b *CallScopeBuilder) Transfer(recipients []common.Address) *CallScopeBuilder {
	b.selectorRules = append(b.selectorRules, SelectorRule{
		Selector:   SelectorTransfer,
		Recipients: recipients,
	})
	return b
}

// Approve allows approve(address,uint256) calls, optionally restricted to the
// given spender addresses.
func (b *CallScopeBuilder) Approve(recipients []common.Address) *CallScopeBuilder {
	b.selectorRules = append(b.selectorRules, SelectorRule{
		Selector:   SelectorApprove,
		Recipients: recipients,
	})
	return b
}

// TransferWithMemo allows transferWithMemo(address,uint256,bytes32) calls,
// optionally restricted to the given recipients.
func (b *CallScopeBuilder) TransferWithMemo(recipients []common.Address) *CallScopeBuilder {
	b.selectorRules = append(b.selectorRules, SelectorRule{
		Selector:   SelectorTransferWithMemo,
		Recipients: recipients,
	})
	return b
}

// Unrestricted allows any call to the target (wildcard selector, no recipient
// filtering).
func (b *CallScopeBuilder) Unrestricted() *CallScopeBuilder {
	b.selectorRules = nil
	return b
}

// Build returns the constructed CallScope.
func (b *CallScopeBuilder) Build() CallScope {
	rules := make([]SelectorRule, len(b.selectorRules))
	copy(rules, b.selectorRules)
	return CallScope{
		Target:        b.target,
		SelectorRules: rules,
	}
}

// TokenLimit represents a per-token spending limit for an access key.
type TokenLimit struct {
	Token  common.Address
	Amount *big.Int
	Period uint64
}

// KeyRestrictions holds all the restrictions for an access key.
type KeyRestrictions struct {
	expiry        uint64
	enforceLimits bool
	limits        []TokenLimit
	allowAnyCalls bool
	allowedCalls  []CallScope
}

// NewKeyRestrictions creates an unrestricted KeyRestrictions with the given
// expiry. Calls are unrestricted by default (allowAnyCalls=true).
func NewKeyRestrictions(expiry uint64) *KeyRestrictions {
	return &KeyRestrictions{
		expiry:        expiry,
		allowAnyCalls: true,
	}
}

// WithEnforceLimits sets the enforceLimits flag.
func (kr *KeyRestrictions) WithEnforceLimits(enforce bool) *KeyRestrictions {
	kr.enforceLimits = enforce
	return kr
}

// WithLimits sets the token spending limits.
func (kr *KeyRestrictions) WithLimits(limits []TokenLimit) *KeyRestrictions {
	kr.limits = limits
	kr.enforceLimits = len(limits) > 0
	return kr
}

// WithAllowedCalls sets the call-scope allowlist and disables allowAnyCalls.
func (kr *KeyRestrictions) WithAllowedCalls(scopes []CallScope) *KeyRestrictions {
	kr.allowedCalls = scopes
	kr.allowAnyCalls = false
	return kr
}

// WithNoCalls sets an empty call-scope allowlist (deny all calls).
func (kr *KeyRestrictions) WithNoCalls() *KeyRestrictions {
	kr.allowedCalls = []CallScope{}
	kr.allowAnyCalls = false
	return kr
}

// IsUnrestricted returns true if calls are unrestricted.
func (kr *KeyRestrictions) IsUnrestricted() bool {
	return kr.allowAnyCalls
}

// IsCallAllowed checks whether a call to target with the given input data is
// permitted by these restrictions.
func (kr *KeyRestrictions) IsCallAllowed(target common.Address, input []byte) bool {
	if kr.allowAnyCalls {
		return true
	}

	// Find a matching scope for the target.
	var scope *CallScope
	for i := range kr.allowedCalls {
		if kr.allowedCalls[i].Target == target {
			scope = &kr.allowedCalls[i]
			break
		}
	}
	if scope == nil {
		return false
	}

	// No selector rules means any call to this target is allowed.
	if len(scope.SelectorRules) == 0 {
		return true
	}

	// Need at least a 4-byte selector in the input.
	if len(input) < 4 {
		return false
	}
	var sel [4]byte
	copy(sel[:], input[:4])

	// Find a matching rule.
	var rule *SelectorRule
	for i := range scope.SelectorRules {
		if scope.SelectorRules[i].Selector == sel {
			rule = &scope.SelectorRules[i]
			break
		}
	}
	if rule == nil {
		return false
	}

	// No recipient filtering.
	if len(rule.Recipients) == 0 {
		return true
	}

	// Need at least selector + 32-byte word for the first argument.
	if len(input) < 36 {
		return false
	}
	recipient := common.BytesToAddress(input[4:36])
	for _, allowed := range rule.Recipients {
		if allowed == recipient {
			return true
		}
	}
	return false
}

// Expiry returns the expiry timestamp.
func (kr *KeyRestrictions) Expiry() uint64 {
	return kr.expiry
}

// Limits returns the token spending limits.
func (kr *KeyRestrictions) Limits() []TokenLimit {
	return kr.limits
}

// AllowedCalls returns the call scope allowlist.
func (kr *KeyRestrictions) AllowedCalls() []CallScope {
	return kr.allowedCalls
}

// Validate checks for conflicting settings.
func (kr *KeyRestrictions) Validate() error {
	if kr.allowAnyCalls && len(kr.allowedCalls) > 0 {
		return errors.New("allowedCalls was provided but allowAnyCalls=true; set allowAnyCalls=false to create a scoped key")
	}
	// Reject duplicate targets — order-dependent IsCallAllowed behaviour is confusing.
	seen := make(map[common.Address]struct{}, len(kr.allowedCalls))
	for _, s := range kr.allowedCalls {
		if _, exists := seen[s.Target]; exists {
			return fmt.Errorf("duplicate CallScope target: %s", s.Target.Hex())
		}
		seen[s.Target] = struct{}{}
	}
	return nil
}
