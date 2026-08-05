package storagecredits

import (
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tempoxyz/tempo-go/pkg/transaction"
)

func selector(sig string) string {
	return "0x" + hex.EncodeToString(crypto.Keccak256([]byte(sig))[:4])
}

func TestSelectors(t *testing.T) {
	cases := map[string]string{
		"setMode(uint8)":          SetModeSelector,
		"setBudget(uint64)":       SetBudgetSelector,
		"balanceOf(address)":      BalanceOfSelector,
		"modeOf(address)":         ModeOfSelector,
		"budgetOf(address)":       BudgetOfSelector,
		"storageCredits(address)": DEXStorageCreditsSelector,
	}
	for sig, want := range cases {
		if got := selector(sig); got != want {
			t.Errorf("%s: expected %s, got %s", sig, want, got)
		}
	}
}

func TestEncodeSelectors(t *testing.T) {
	account := common.HexToAddress("0x1111111111111111111111111111111111111111")
	cases := []struct {
		name     string
		call     func() (Call, error)
		to       common.Address
		selector string
	}{
		{"SetMode", func() (Call, error) { return SetMode(ModeDirect) }, storageCreditsAddress, SetModeSelector},
		{"SetBudget", func() (Call, error) { return SetBudget(5) }, storageCreditsAddress, SetBudgetSelector},
		{"BalanceOf", func() (Call, error) { return BalanceOf(account) }, storageCreditsAddress, BalanceOfSelector},
		{"ModeOf", func() (Call, error) { return ModeOf(account) }, storageCreditsAddress, ModeOfSelector},
		{"BudgetOf", func() (Call, error) { return BudgetOf(account) }, storageCreditsAddress, BudgetOfSelector},
		{"DEXStorageCredits", func() (Call, error) { return DEXStorageCredits(account) }, transaction.StablecoinDEXAddress, DEXStorageCreditsSelector},
	}
	for _, tc := range cases {
		call, err := tc.call()
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", tc.name, err)
		}
		if call.To != tc.to {
			t.Errorf("%s: unexpected target %s", tc.name, call.To.Hex())
		}
		if got := "0x" + hex.EncodeToString(call.Data[:4]); got != tc.selector {
			t.Errorf("%s: expected selector %s, got %s", tc.name, tc.selector, got)
		}
	}
}

func TestEncodeArgsRoundTrip(t *testing.T) {
	account := common.HexToAddress("0x2222222222222222222222222222222222222222")

	modeCall, _ := SetMode(ModeDirect)
	args, err := setModeABI.Methods["setMode"].Inputs.Unpack(modeCall.Data[4:])
	if err != nil {
		t.Fatalf("setMode unpack: %v", err)
	}
	if args[0].(uint8) != uint8(ModeDirect) {
		t.Errorf("setMode arg: got %d", args[0])
	}

	budgetCall, _ := SetBudget(7)
	args, err = setBudgetABI.Methods["setBudget"].Inputs.Unpack(budgetCall.Data[4:])
	if err != nil {
		t.Fatalf("setBudget unpack: %v", err)
	}
	if args[0].(uint64) != 7 {
		t.Errorf("setBudget arg: got %d", args[0])
	}

	balCall, _ := BalanceOf(account)
	args, err = balanceOfABI.Methods["balanceOf"].Inputs.Unpack(balCall.Data[4:])
	if err != nil {
		t.Fatalf("balanceOf unpack: %v", err)
	}
	if args[0].(common.Address) != account {
		t.Errorf("balanceOf arg: got %s", args[0])
	}
}

func TestSetModeRejectsInvalid(t *testing.T) {
	if _, err := SetMode(Mode(3)); err == nil {
		t.Error("expected error for invalid mode, got nil")
	}
	for _, m := range []Mode{ModeRefund, ModePreserve, ModeDirect} {
		if _, err := SetMode(m); err != nil {
			t.Errorf("mode %d: unexpected error: %v", m, err)
		}
	}
}

func TestParseUint64Result(t *testing.T) {
	encoded, err := balanceOfABI.Methods["balanceOf"].Outputs.Pack(uint64(42))
	if err != nil {
		t.Fatalf("failed to pack: %v", err)
	}
	got, err := ParseUint64Result(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 42 {
		t.Errorf("expected 42, got %d", got)
	}

	for _, tc := range []struct {
		name   string
		result []byte
	}{
		{"short", encoded[:len(encoded)-1]},
		{"trailing data", append(append([]byte{}, encoded...), make([]byte, 32)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseUint64Result(tc.result); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestParseModeResult(t *testing.T) {
	encoded, err := modeOfABI.Methods["modeOf"].Outputs.Pack(uint8(ModePreserve))
	if err != nil {
		t.Fatalf("failed to pack: %v", err)
	}
	got, err := ParseModeResult(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != ModePreserve {
		t.Errorf("expected %d, got %d", ModePreserve, got)
	}

	for _, tc := range []struct {
		name   string
		result []byte
	}{
		{"short", encoded[:len(encoded)-1]},
		{"trailing data", append(append([]byte{}, encoded...), make([]byte, 32)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseModeResult(tc.result); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}

	invalid, err := modeOfABI.Methods["modeOf"].Outputs.Pack(uint8(ModeDirect + 1))
	if err != nil {
		t.Fatalf("failed to pack invalid mode: %v", err)
	}
	if _, err := ParseModeResult(invalid); err == nil {
		t.Fatal("expected error for invalid mode, got nil")
	}
}
