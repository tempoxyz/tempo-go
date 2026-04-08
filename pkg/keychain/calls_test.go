package keychain

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestAuthorizeKey_Encodes(t *testing.T) {
	keyID := common.HexToAddress("0x1111111111111111111111111111111111111111")
	kr := NewKeyRestrictions(1000)

	call, err := AuthorizeKey(keyID, SignatureTypeSecp256k1, kr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if call.To != keychainAddress {
		t.Errorf("expected to=%s, got %s", keychainAddress.Hex(), call.To.Hex())
	}
	if len(call.Data) < 4 {
		t.Fatal("calldata too short")
	}
}

func TestAuthorizeKey_WithAllowedCalls(t *testing.T) {
	keyID := common.HexToAddress("0x1111111111111111111111111111111111111111")
	token := common.HexToAddress("0x20c0000000000000000000000000000000000001")
	scope := NewCallScopeBuilder(token).Transfer(nil).Build()

	kr := NewKeyRestrictions(1000).WithAllowedCalls([]CallScope{scope})

	call, err := AuthorizeKey(keyID, SignatureTypeSecp256k1, kr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(call.Data) < 4 {
		t.Fatal("calldata too short")
	}
}

func TestAuthorizeKey_NilRestrictions(t *testing.T) {
	keyID := common.HexToAddress("0x1111111111111111111111111111111111111111")
	_, err := AuthorizeKey(keyID, SignatureTypeSecp256k1, nil)
	if err == nil {
		t.Error("expected error for nil restrictions")
	}
}

func TestAuthorizeKey_RejectsConflict(t *testing.T) {
	keyID := common.HexToAddress("0x1111111111111111111111111111111111111111")
	token := common.HexToAddress("0x20c0000000000000000000000000000000000001")
	scope := NewCallScopeBuilder(token).Transfer(nil).Build()

	kr := NewKeyRestrictions(1000)
	kr.allowAnyCalls = true
	kr.allowedCalls = []CallScope{scope}

	_, err := AuthorizeKey(keyID, SignatureTypeSecp256k1, kr)
	if err == nil {
		t.Error("expected error for conflicting allowAnyCalls + allowedCalls")
	}
}

func TestAuthorizeKey_WithRecipients(t *testing.T) {
	keyID := common.HexToAddress("0x1111111111111111111111111111111111111111")
	token := common.HexToAddress("0x20c0000000000000000000000000000000000001")
	recipient := common.HexToAddress("0x3333333333333333333333333333333333333333")
	scope := NewCallScopeBuilder(token).Transfer([]common.Address{recipient}).Build()

	kr := NewKeyRestrictions(1000).WithAllowedCalls([]CallScope{scope})

	call, err := AuthorizeKey(keyID, SignatureTypeSecp256k1, kr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(call.Data) < 4 {
		t.Fatal("calldata too short")
	}
}

func TestRevokeKey_Encodes(t *testing.T) {
	keyID := common.HexToAddress("0x1111111111111111111111111111111111111111")

	call, err := RevokeKey(keyID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if call.To != keychainAddress {
		t.Errorf("expected to=%s, got %s", keychainAddress.Hex(), call.To.Hex())
	}
	if len(call.Data) < 4 {
		t.Fatal("calldata too short")
	}
}

func TestSetAllowedCalls_Encodes(t *testing.T) {
	keyID := common.HexToAddress("0x1111111111111111111111111111111111111111")
	token := common.HexToAddress("0x20c0000000000000000000000000000000000001")
	scope := NewCallScopeBuilder(token).Transfer(nil).Build()

	call, err := SetAllowedCalls(keyID, []CallScope{scope})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if call.To != keychainAddress {
		t.Errorf("expected to=%s, got %s", keychainAddress.Hex(), call.To.Hex())
	}
	if len(call.Data) < 4 {
		t.Fatal("calldata too short")
	}
}

func TestSetAllowedCalls_WithRecipients(t *testing.T) {
	keyID := common.HexToAddress("0x1111111111111111111111111111111111111111")
	token := common.HexToAddress("0x20c0000000000000000000000000000000000001")
	recipient := common.HexToAddress("0x3333333333333333333333333333333333333333")
	scope := NewCallScopeBuilder(token).Transfer([]common.Address{recipient}).Build()

	call, err := SetAllowedCalls(keyID, []CallScope{scope})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(call.Data) < 4 {
		t.Fatal("calldata too short")
	}
}

func TestSetAllowedCalls_WithSelector(t *testing.T) {
	keyID := common.HexToAddress("0x1111111111111111111111111111111111111111")
	target := common.HexToAddress("0x2222222222222222222222222222222222222222")
	sel := [4]byte{0xaa, 0xbb, 0xcc, 0xdd}
	scope := NewCallScopeBuilder(target).WithSelector(sel).Build()

	call, err := SetAllowedCalls(keyID, []CallScope{scope})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(call.Data) < 4 {
		t.Fatal("calldata too short")
	}
}

func TestRemoveAllowedCalls_Encodes(t *testing.T) {
	keyID := common.HexToAddress("0x1111111111111111111111111111111111111111")
	target := common.HexToAddress("0x2222222222222222222222222222222222222222")

	call, err := RemoveAllowedCalls(keyID, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if call.To != keychainAddress {
		t.Errorf("expected to=%s, got %s", keychainAddress.Hex(), call.To.Hex())
	}
	if len(call.Data) < 4 {
		t.Fatal("calldata too short")
	}
}

func TestUpdateSpendingLimit_Encodes(t *testing.T) {
	keyID := common.HexToAddress("0x1111111111111111111111111111111111111111")
	token := common.HexToAddress("0x20c0000000000000000000000000000000000001")

	call, err := UpdateSpendingLimit(keyID, token, big.NewInt(1000))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if call.To != keychainAddress {
		t.Errorf("expected to=%s, got %s", keychainAddress.Hex(), call.To.Hex())
	}
	if len(call.Data) < 4 {
		t.Fatal("calldata too short")
	}
}

func TestFunctionSelectors_Calls(t *testing.T) {
	tests := []struct {
		name     string
		selector string
		sig      string
	}{
		{"SetAllowedCalls", SetAllowedCallsSelector, "setAllowedCalls(address,(address,(bytes4,address[])[])[])"}, //nolint:lll
		{"RemoveAllowedCalls", RemoveAllowedCallsSelector, "removeAllowedCalls(address,address)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := crypto.Keccak256([]byte(tt.sig))
			got := "0x" + hex.EncodeToString(hash[:4])
			if got != tt.selector {
				t.Errorf("selector mismatch for %s: expected %s, got %s", tt.sig, tt.selector, got)
			}
		})
	}
}
