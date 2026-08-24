package keychain

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

var (
	testKey   = common.HexToAddress("0x1111111111111111111111111111111111111111")
	testToken = common.HexToAddress("0x20c0000000000000000000000000000000000001")
)

func TestKeyRestrictions_Validate_RejectsBadLimitAmounts(t *testing.T) {
	over := new(big.Int).Lsh(big.NewInt(1), 256) // 2^256, exceeds uint256

	cases := map[string]*big.Int{
		"nil":      nil,
		"negative": big.NewInt(-1),
		"overflow": over,
	}
	for name, amt := range cases {
		t.Run(name, func(t *testing.T) {
			kr := NewKeyRestrictions(0).WithLimits([]TokenLimit{{Token: testToken, Amount: amt}})
			if err := kr.Validate(); err == nil {
				t.Fatalf("expected Validate to reject %s amount", name)
			}
		})
	}
}

// AuthorizeKey must return an error (not panic) for an invalid limit amount.
func TestAuthorizeKey_NilLimitAmountReturnsError(t *testing.T) {
	kr := NewKeyRestrictions(0).WithLimits([]TokenLimit{{Token: testToken, Amount: nil}})
	if _, err := AuthorizeKey(testKey, SignatureTypeSecp256k1, kr); err == nil {
		t.Fatal("expected AuthorizeKey to return an error for nil limit amount")
	}
}

// A valid limit still packs successfully.
func TestAuthorizeKey_ValidLimitSucceeds(t *testing.T) {
	kr := NewKeyRestrictions(0).WithLimits([]TokenLimit{{Token: testToken, Amount: big.NewInt(1000)}})
	if _, err := AuthorizeKey(testKey, SignatureTypeSecp256k1, kr); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUpdateSpendingLimit_RejectsBadAmounts(t *testing.T) {
	if _, err := UpdateSpendingLimit(testKey, testToken, nil); err == nil {
		t.Fatal("expected error for nil newLimit")
	}
	if _, err := UpdateSpendingLimit(testKey, testToken, big.NewInt(-5)); err == nil {
		t.Fatal("expected error for negative newLimit")
	}
	if _, err := UpdateSpendingLimit(testKey, testToken, big.NewInt(500)); err != nil {
		t.Fatalf("unexpected error for valid newLimit: %v", err)
	}
}
