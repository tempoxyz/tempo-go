package storagecredits

import (
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/tempoxyz/tempo-go/pkg/transaction"
)

// StorageCreditsAddress is the address of the TIP-1060 storage credits precompile.
const StorageCreditsAddress = "0x1060000000000000000000000000000000000000"

// Function selectors for the TIP-1060 storage credits precompile.
const (
	// SetModeSelector is the selector for setMode(uint8).
	SetModeSelector = "0x21175b4a"
	// SetBudgetSelector is the selector for setBudget(uint64).
	SetBudgetSelector = "0xffe295c3"
	// BalanceOfSelector is the selector for balanceOf(address).
	BalanceOfSelector = "0x70a08231"
	// ModeOfSelector is the selector for modeOf(address).
	ModeOfSelector = "0x13668995"
	// BudgetOfSelector is the selector for budgetOf(address).
	BudgetOfSelector = "0x7865e71f"
	// DEXStorageCreditsSelector is the selector for the StablecoinDEX
	// storageCredits(address) view (TIP-1064).
	DEXStorageCreditsSelector = "0x4d65338b"
)

// Mode is an account's storage creation mode as defined by TIP-1060.
type Mode uint8

const (
	// ModeRefund charges the credit value upfront and refunds it at
	// end-of-transaction if a credit is available. It is the default.
	ModeRefund Mode = 0
	// ModePreserve always charges the credit value and never consumes credits.
	ModePreserve Mode = 1
	// ModeDirect consumes an available credit synchronously, bounded by the
	// account's Direct budget.
	ModeDirect Mode = 2
)

// Call represents an EVM call with target address and calldata.
type Call struct {
	To   common.Address
	Data []byte
}

var storageCreditsAddress = common.HexToAddress(StorageCreditsAddress)

var (
	setModeABI           abi.ABI
	setBudgetABI         abi.ABI
	balanceOfABI         abi.ABI
	modeOfABI            abi.ABI
	budgetOfABI          abi.ABI
	dexStorageCreditsABI abi.ABI
)

func mustParseABI(json string) abi.ABI {
	parsed, err := abi.JSON(strings.NewReader(json))
	if err != nil {
		panic(fmt.Sprintf("failed to parse ABI: %v", err))
	}
	return parsed
}

func init() {
	setModeABI = mustParseABI(`[{
		"name": "setMode",
		"type": "function",
		"inputs": [{"name": "newMode", "type": "uint8"}]
	}]`)

	setBudgetABI = mustParseABI(`[{
		"name": "setBudget",
		"type": "function",
		"inputs": [{"name": "creditBudget", "type": "uint64"}]
	}]`)

	balanceOfABI = mustParseABI(`[{
		"name": "balanceOf",
		"type": "function",
		"inputs": [{"name": "account", "type": "address"}],
		"outputs": [{"name": "", "type": "uint64"}]
	}]`)

	modeOfABI = mustParseABI(`[{
		"name": "modeOf",
		"type": "function",
		"inputs": [{"name": "account", "type": "address"}],
		"outputs": [{"name": "", "type": "uint8"}]
	}]`)

	budgetOfABI = mustParseABI(`[{
		"name": "budgetOf",
		"type": "function",
		"inputs": [{"name": "account", "type": "address"}],
		"outputs": [{"name": "", "type": "uint64"}]
	}]`)

	dexStorageCreditsABI = mustParseABI(`[{
		"name": "storageCredits",
		"type": "function",
		"inputs": [{"name": "user", "type": "address"}],
		"outputs": [{"name": "credits", "type": "uint64"}]
	}]`)
}

// GetStorageCreditsAddress returns the TIP-1060 precompile address.
func GetStorageCreditsAddress() common.Address {
	return storageCreditsAddress
}

// SetMode builds a setMode(uint8) call that sets the caller's storage creation
// mode for the current transaction. The precompile rejects modes outside
// {Refund, Preserve, Direct}, so those are rejected here too.
func SetMode(mode Mode) (Call, error) {
	if mode != ModeRefund && mode != ModePreserve && mode != ModeDirect {
		return Call{}, fmt.Errorf("invalid storage creation mode: %d", mode)
	}
	data, err := setModeABI.Pack("setMode", uint8(mode))
	if err != nil {
		return Call{}, fmt.Errorf("failed to encode setMode: %w", err)
	}
	return Call{To: storageCreditsAddress, Data: data}, nil
}

// SetBudget builds a setBudget(uint64) call that switches the caller to Direct
// mode with the given credit budget for the current transaction.
func SetBudget(creditBudget uint64) (Call, error) {
	data, err := setBudgetABI.Pack("setBudget", creditBudget)
	if err != nil {
		return Call{}, fmt.Errorf("failed to encode setBudget: %w", err)
	}
	return Call{To: storageCreditsAddress, Data: data}, nil
}

// BalanceOf builds a balanceOf(address) call. Parse the result with
// ParseUint64Result.
func BalanceOf(account common.Address) (Call, error) {
	data, err := balanceOfABI.Pack("balanceOf", account)
	if err != nil {
		return Call{}, fmt.Errorf("failed to encode balanceOf: %w", err)
	}
	return Call{To: storageCreditsAddress, Data: data}, nil
}

// ModeOf builds a modeOf(address) call. Parse the result with ParseModeResult.
func ModeOf(account common.Address) (Call, error) {
	data, err := modeOfABI.Pack("modeOf", account)
	if err != nil {
		return Call{}, fmt.Errorf("failed to encode modeOf: %w", err)
	}
	return Call{To: storageCreditsAddress, Data: data}, nil
}

// BudgetOf builds a budgetOf(address) call. Parse the result with
// ParseUint64Result.
func BudgetOf(account common.Address) (Call, error) {
	data, err := budgetOfABI.Pack("budgetOf", account)
	if err != nil {
		return Call{}, fmt.Errorf("failed to encode budgetOf: %w", err)
	}
	return Call{To: storageCreditsAddress, Data: data}, nil
}

// DEXStorageCredits builds a storageCredits(address) call against the
// StablecoinDEX precompile (TIP-1064). Parse the result with ParseUint64Result.
func DEXStorageCredits(user common.Address) (Call, error) {
	data, err := dexStorageCreditsABI.Pack("storageCredits", user)
	if err != nil {
		return Call{}, fmt.Errorf("failed to encode storageCredits: %w", err)
	}
	return Call{To: transaction.StablecoinDEXAddress, Data: data}, nil
}

// ParseUint64Result decodes a single uint64 returned by balanceOf, budgetOf, or
// storageCredits.
func ParseUint64Result(result []byte) (uint64, error) {
	values, err := balanceOfABI.Unpack("balanceOf", result)
	if err != nil {
		return 0, fmt.Errorf("failed to decode uint64 result: %w", err)
	}
	if len(values) != 1 {
		return 0, fmt.Errorf("expected 1 return value, got %d", len(values))
	}
	return values[0].(uint64), nil
}

// ParseModeResult decodes the Mode returned by modeOf.
func ParseModeResult(result []byte) (Mode, error) {
	values, err := modeOfABI.Unpack("modeOf", result)
	if err != nil {
		return 0, fmt.Errorf("failed to decode modeOf result: %w", err)
	}
	if len(values) != 1 {
		return 0, fmt.Errorf("expected 1 return value, got %d", len(values))
	}
	return Mode(values[0].(uint8)), nil
}
