package keychain

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestCallScopeBuilder_Build(t *testing.T) {
	target := common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	scope := NewCallScopeBuilder(target).Build()

	if scope.Target != target {
		t.Errorf("expected target %s, got %s", target.Hex(), scope.Target.Hex())
	}
	if len(scope.SelectorRules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(scope.SelectorRules))
	}
}

func TestCallScopeBuilder_WithSelector(t *testing.T) {
	target := common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	sel := [4]byte{0xaa, 0xbb, 0xcc, 0xdd}
	scope := NewCallScopeBuilder(target).WithSelector(sel).Build()

	if len(scope.SelectorRules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(scope.SelectorRules))
	}
	if scope.SelectorRules[0].Selector != sel {
		t.Errorf("selector mismatch")
	}
	if len(scope.SelectorRules[0].Recipients) != 0 {
		t.Errorf("expected 0 recipients, got %d", len(scope.SelectorRules[0].Recipients))
	}
}

func TestCallScopeBuilder_Transfer(t *testing.T) {
	target := common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	recipient := common.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	scope := NewCallScopeBuilder(target).Transfer([]common.Address{recipient}).Build()

	if len(scope.SelectorRules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(scope.SelectorRules))
	}
	if scope.SelectorRules[0].Selector != SelectorTransfer {
		t.Errorf("expected transfer selector")
	}
	if len(scope.SelectorRules[0].Recipients) != 1 {
		t.Errorf("expected 1 recipient, got %d", len(scope.SelectorRules[0].Recipients))
	}
}

func TestCallScopeBuilder_TransferNoRecipients(t *testing.T) {
	target := common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	scope := NewCallScopeBuilder(target).Transfer(nil).Build()

	if scope.SelectorRules[0].Selector != SelectorTransfer {
		t.Errorf("expected transfer selector")
	}
	if len(scope.SelectorRules[0].Recipients) != 0 {
		t.Errorf("expected 0 recipients")
	}
}

func TestCallScopeBuilder_Approve(t *testing.T) {
	target := common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	scope := NewCallScopeBuilder(target).Approve(nil).Build()

	if scope.SelectorRules[0].Selector != SelectorApprove {
		t.Errorf("expected approve selector")
	}
}

func TestCallScopeBuilder_TransferWithMemo(t *testing.T) {
	target := common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	scope := NewCallScopeBuilder(target).TransferWithMemo(nil).Build()

	if scope.SelectorRules[0].Selector != SelectorTransferWithMemo {
		t.Errorf("expected transferWithMemo selector")
	}
}

func TestCallScopeBuilder_Chained(t *testing.T) {
	target := common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	scope := NewCallScopeBuilder(target).
		Transfer(nil).
		Approve(nil).
		Build()

	if len(scope.SelectorRules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(scope.SelectorRules))
	}
}

func TestCallScopeBuilder_Unrestricted(t *testing.T) {
	target := common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	scope := NewCallScopeBuilder(target).
		Transfer(nil).
		Unrestricted().
		Build()

	if len(scope.SelectorRules) != 0 {
		t.Errorf("expected 0 rules after unrestricted, got %d", len(scope.SelectorRules))
	}
}

func TestKeyRestrictions_IsUnrestricted(t *testing.T) {
	kr := NewKeyRestrictions(0)
	if !kr.IsUnrestricted() {
		t.Error("default should be unrestricted")
	}
}

func TestKeyRestrictions_WithAllowedCalls(t *testing.T) {
	target := common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	scope := NewCallScopeBuilder(target).Transfer(nil).Build()

	kr := NewKeyRestrictions(0).WithAllowedCalls([]CallScope{scope})
	if kr.IsUnrestricted() {
		t.Error("should not be unrestricted after WithAllowedCalls")
	}
	if len(kr.AllowedCalls()) != 1 {
		t.Errorf("expected 1 scope, got %d", len(kr.AllowedCalls()))
	}
}

func TestKeyRestrictions_WithNoCalls(t *testing.T) {
	kr := NewKeyRestrictions(0).WithNoCalls()
	if kr.IsUnrestricted() {
		t.Error("should not be unrestricted")
	}
	if len(kr.AllowedCalls()) != 0 {
		t.Errorf("expected 0 scopes, got %d", len(kr.AllowedCalls()))
	}
}

func TestKeyRestrictions_Validate(t *testing.T) {
	target := common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	scope := NewCallScopeBuilder(target).Build()

	// allowAnyCalls=true with non-empty allowedCalls should fail.
	kr := NewKeyRestrictions(0)
	kr.allowedCalls = []CallScope{scope}
	kr.allowAnyCalls = true

	if err := kr.Validate(); err == nil {
		t.Error("expected validation error")
	}
}

func TestKeyRestrictions_WithLimits(t *testing.T) {
	kr := NewKeyRestrictions(1000).WithLimits([]TokenLimit{
		{Token: common.HexToAddress("0x20c0000000000000000000000000000000000001"), Amount: big.NewInt(100), Period: 0},
	})
	if !kr.enforceLimits {
		t.Error("enforceLimits should be true when limits are set")
	}
	if len(kr.Limits()) != 1 {
		t.Errorf("expected 1 limit, got %d", len(kr.Limits()))
	}
}

func TestKeyRestrictions_ValidateRejectsDuplicateTargets(t *testing.T) {
	target := common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	scope1 := NewCallScopeBuilder(target).Transfer(nil).Build()
	scope2 := NewCallScopeBuilder(target).Approve(nil).Build()

	kr := NewKeyRestrictions(0).WithAllowedCalls([]CallScope{scope1, scope2})
	if err := kr.Validate(); err == nil {
		t.Error("expected error for duplicate targets")
	}
}

// --- IsCallAllowed tests ---

func TestIsCallAllowed_Unrestricted(t *testing.T) {
	kr := NewKeyRestrictions(0)
	target := common.HexToAddress("0x2222222222222222222222222222222222222222")
	if !kr.IsCallAllowed(target, nil) {
		t.Error("unrestricted should allow any call")
	}
	if !kr.IsCallAllowed(target, []byte{0xaa, 0xbb, 0xcc, 0xdd}) {
		t.Error("unrestricted should allow any call with data")
	}
}

func TestIsCallAllowed_NoCalls(t *testing.T) {
	kr := NewKeyRestrictions(0).WithNoCalls()
	target := common.HexToAddress("0x2222222222222222222222222222222222222222")
	if kr.IsCallAllowed(target, []byte{0xaa, 0xbb, 0xcc, 0xdd}) {
		t.Error("no-calls should deny everything")
	}
}

func TestIsCallAllowed_TargetNotInScope(t *testing.T) {
	token := common.HexToAddress("0x20c0000000000000000000000000000000000001")
	other := common.HexToAddress("0x3333333333333333333333333333333333333333")
	kr := NewKeyRestrictions(0).WithAllowedCalls([]CallScope{
		NewCallScopeBuilder(token).Build(),
	})
	if kr.IsCallAllowed(other, []byte{0xaa, 0xbb, 0xcc, 0xdd}) {
		t.Error("call to non-scoped target should be denied")
	}
}

func TestIsCallAllowed_NoSelectorRulesAllowsAny(t *testing.T) {
	token := common.HexToAddress("0x20c0000000000000000000000000000000000001")
	kr := NewKeyRestrictions(0).WithAllowedCalls([]CallScope{
		NewCallScopeBuilder(token).Build(),
	})
	if !kr.IsCallAllowed(token, []byte{0xaa, 0xbb, 0xcc, 0xdd}) {
		t.Error("no selector rules should allow any call to target")
	}
	if !kr.IsCallAllowed(token, nil) {
		t.Error("no selector rules should allow empty input")
	}
}

func TestIsCallAllowed_SelectorMatch(t *testing.T) {
	token := common.HexToAddress("0x20c0000000000000000000000000000000000001")
	sel := [4]byte{0xaa, 0xbb, 0xcc, 0xdd}
	kr := NewKeyRestrictions(0).WithAllowedCalls([]CallScope{
		NewCallScopeBuilder(token).WithSelector(sel).Build(),
	})

	if !kr.IsCallAllowed(token, []byte{0xaa, 0xbb, 0xcc, 0xdd}) {
		t.Error("matching selector should be allowed")
	}
	if kr.IsCallAllowed(token, []byte{0x11, 0x22, 0x33, 0x44}) {
		t.Error("non-matching selector should be denied")
	}
	if kr.IsCallAllowed(token, []byte{0xaa, 0xbb}) {
		t.Error("too-short input should be denied")
	}
}

func TestIsCallAllowed_TransferWithRecipients(t *testing.T) {
	token := common.HexToAddress("0x20c0000000000000000000000000000000000001")
	allowed := common.HexToAddress("0x4444444444444444444444444444444444444444")
	denied := common.HexToAddress("0x5555555555555555555555555555555555555555")

	kr := NewKeyRestrictions(0).WithAllowedCalls([]CallScope{
		NewCallScopeBuilder(token).Transfer([]common.Address{allowed}).Build(),
	})

	// Build valid transfer calldata: selector + padded address + amount
	input := make([]byte, 0, 68)
	input = append(input, SelectorTransfer[:]...)
	// left-pad address to 32 bytes
	padded := make([]byte, 12)
	input = append(input, padded...)
	input = append(input, allowed.Bytes()...)
	// amount (32 bytes of zeros)
	input = append(input, make([]byte, 32)...)

	if !kr.IsCallAllowed(token, input) {
		t.Error("transfer to allowed recipient should be permitted")
	}

	// Same selector, different recipient
	badInput := make([]byte, 0, 68)
	badInput = append(badInput, SelectorTransfer[:]...)
	badInput = append(badInput, make([]byte, 12)...)
	badInput = append(badInput, denied.Bytes()...)
	badInput = append(badInput, make([]byte, 32)...)

	if kr.IsCallAllowed(token, badInput) {
		t.Error("transfer to denied recipient should not be permitted")
	}
}

func TestIsCallAllowed_NoRecipientsAllowsAny(t *testing.T) {
	token := common.HexToAddress("0x20c0000000000000000000000000000000000001")
	anyone := common.HexToAddress("0x9999999999999999999999999999999999999999")

	kr := NewKeyRestrictions(0).WithAllowedCalls([]CallScope{
		NewCallScopeBuilder(token).Transfer(nil).Build(),
	})

	input := make([]byte, 0, 68)
	input = append(input, SelectorTransfer[:]...)
	input = append(input, make([]byte, 12)...)
	input = append(input, anyone.Bytes()...)
	input = append(input, make([]byte, 32)...)

	if !kr.IsCallAllowed(token, input) {
		t.Error("transfer with no recipient restriction should allow anyone")
	}
}

func TestIsCallAllowed_RecipientWordTooShort(t *testing.T) {
	token := common.HexToAddress("0x20c0000000000000000000000000000000000001")
	allowed := common.HexToAddress("0x4444444444444444444444444444444444444444")

	kr := NewKeyRestrictions(0).WithAllowedCalls([]CallScope{
		NewCallScopeBuilder(token).Transfer([]common.Address{allowed}).Build(),
	})

	// Only selector, no recipient word.
	input := SelectorTransfer[:]
	if kr.IsCallAllowed(token, input) {
		t.Error("input without recipient word should be denied")
	}
}
