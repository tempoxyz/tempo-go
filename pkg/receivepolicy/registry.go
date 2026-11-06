package receivepolicy

import (
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// TIP403RegistryAddress is the address of the TIP-403 registry precompile.
const TIP403RegistryAddress = "0x403C000000000000000000000000000000000000"

// Function selectors for the T6/TIP-1028 receive-policy functions.
const (
	// SetReceivePolicySelector is the selector for setReceivePolicy(uint64,uint64,address).
	SetReceivePolicySelector = "0xdda03d86"
	// ReceivePolicySelector is the selector for receivePolicy(address).
	ReceivePolicySelector = "0xe111e611"
	// ValidateReceivePolicySelector is the selector for validateReceivePolicy(address,address,address).
	ValidateReceivePolicySelector = "0xb72b0c59"
)

// PolicyType matches the ITIP403Registry.PolicyType enum.
const (
	PolicyTypeWhitelist = 0
	PolicyTypeBlacklist = 1
	PolicyTypeCompound  = 2
)

// BlockedReason matches the ITIP403Registry.BlockedReason enum. It is the reason
// an inbound transfer or mint was blocked by a receive policy.
const (
	BlockedReasonNone          = 0
	BlockedReasonTokenFilter   = 1
	BlockedReasonReceivePolicy = 2
)

// Call represents an EVM call with target address and calldata.
type Call struct {
	To   common.Address
	Data []byte
}

// ReceivePolicy is an account's receive-policy configuration as returned by
// receivePolicy(address).
type ReceivePolicy struct {
	HasReceivePolicy  bool
	SenderPolicyID    uint64
	SenderPolicyType  uint8
	TokenFilterID     uint64
	TokenFilterType   uint8
	RecoveryAuthority common.Address
}

var tip403RegistryAddress = common.HexToAddress(TIP403RegistryAddress)

var (
	setReceivePolicyABI      abi.ABI
	receivePolicyABI         abi.ABI
	validateReceivePolicyABI abi.ABI
)

func mustParseABI(json string) abi.ABI {
	parsed, err := abi.JSON(strings.NewReader(json))
	if err != nil {
		panic(fmt.Sprintf("failed to parse ABI: %v", err))
	}
	return parsed
}

func init() {
	setReceivePolicyABI = mustParseABI(`[{
		"name": "setReceivePolicy",
		"type": "function",
		"inputs": [
			{"name": "senderPolicyId", "type": "uint64"},
			{"name": "tokenFilterId", "type": "uint64"},
			{"name": "recoveryAuthority", "type": "address"}
		]
	}]`)

	receivePolicyABI = mustParseABI(`[{
		"name": "receivePolicy",
		"type": "function",
		"inputs": [
			{"name": "account", "type": "address"}
		],
		"outputs": [
			{"name": "hasReceivePolicy", "type": "bool"},
			{"name": "senderPolicyId", "type": "uint64"},
			{"name": "senderPolicyType", "type": "uint8"},
			{"name": "tokenFilterId", "type": "uint64"},
			{"name": "tokenFilterType", "type": "uint8"},
			{"name": "recoveryAuthority", "type": "address"}
		]
	}]`)

	validateReceivePolicyABI = mustParseABI(`[{
		"name": "validateReceivePolicy",
		"type": "function",
		"inputs": [
			{"name": "token", "type": "address"},
			{"name": "sender", "type": "address"},
			{"name": "receiver", "type": "address"}
		],
		"outputs": [
			{"name": "authorized", "type": "bool"},
			{"name": "blockedReason", "type": "uint8"}
		]
	}]`)
}

// GetTIP403RegistryAddress returns the TIP-403 registry precompile address.
func GetTIP403RegistryAddress() common.Address {
	return tip403RegistryAddress
}

// SetReceivePolicy builds a setReceivePolicy(uint64,uint64,address) call.
//
// It sets the caller's receive policy. senderPolicyID and tokenFilterID are
// TIP-403 policy IDs; the built-in policies 0 (reject all) and 1 (allow all)
// are also valid, so use 1 and 1 to effectively disable filtering.
// recoveryAuthority is who may claim blocked funds: the zero address means the
// transfer originator, and any nonzero address names that claimer.
func SetReceivePolicy(senderPolicyID, tokenFilterID uint64, recoveryAuthority common.Address) (Call, error) {
	data, err := setReceivePolicyABI.Pack("setReceivePolicy", senderPolicyID, tokenFilterID, recoveryAuthority)
	if err != nil {
		return Call{}, fmt.Errorf("failed to encode setReceivePolicy: %w", err)
	}
	return Call{To: tip403RegistryAddress, Data: data}, nil
}

// ReceivePolicyCall builds a receivePolicy(address) call. Parse the result with
// ParseReceivePolicyResult.
func ReceivePolicyCall(account common.Address) (Call, error) {
	data, err := receivePolicyABI.Pack("receivePolicy", account)
	if err != nil {
		return Call{}, fmt.Errorf("failed to encode receivePolicy: %w", err)
	}
	return Call{To: tip403RegistryAddress, Data: data}, nil
}

// ParseReceivePolicyResult parses the result of a receivePolicy call.
func ParseReceivePolicyResult(result []byte) (ReceivePolicy, error) {
	if len(result) != 6*32 {
		return ReceivePolicy{}, fmt.Errorf("invalid receivePolicy result length: expected %d, got %d", 6*32, len(result))
	}
	values, err := receivePolicyABI.Unpack("receivePolicy", result)
	if err != nil {
		return ReceivePolicy{}, fmt.Errorf("failed to decode receivePolicy result: %w", err)
	}
	if len(values) != 6 {
		return ReceivePolicy{}, fmt.Errorf("expected 6 return values, got %d", len(values))
	}
	return ReceivePolicy{
		HasReceivePolicy:  values[0].(bool),
		SenderPolicyID:    values[1].(uint64),
		SenderPolicyType:  values[2].(uint8),
		TokenFilterID:     values[3].(uint64),
		TokenFilterType:   values[4].(uint8),
		RecoveryAuthority: values[5].(common.Address),
	}, nil
}

// ValidateReceivePolicy builds a validateReceivePolicy(address,address,address)
// call. It checks whether sender may send token to receiver. Parse the result
// with ParseValidateReceivePolicyResult.
func ValidateReceivePolicy(token, sender, receiver common.Address) (Call, error) {
	data, err := validateReceivePolicyABI.Pack("validateReceivePolicy", token, sender, receiver)
	if err != nil {
		return Call{}, fmt.Errorf("failed to encode validateReceivePolicy: %w", err)
	}
	return Call{To: tip403RegistryAddress, Data: data}, nil
}

// ParseValidateReceivePolicyResult parses the result of a validateReceivePolicy
// call. authorized is true when the transfer is allowed; otherwise blockedReason
// holds the reason (one of the BlockedReason constants).
func ParseValidateReceivePolicyResult(result []byte) (authorized bool, blockedReason uint8, err error) {
	if len(result) != 2*32 {
		return false, 0, fmt.Errorf("invalid validateReceivePolicy result length: expected %d, got %d", 2*32, len(result))
	}
	values, err := validateReceivePolicyABI.Unpack("validateReceivePolicy", result)
	if err != nil {
		return false, 0, fmt.Errorf("failed to decode validateReceivePolicy result: %w", err)
	}
	if len(values) != 2 {
		return false, 0, fmt.Errorf("expected 2 return values, got %d", len(values))
	}
	return values[0].(bool), values[1].(uint8), nil
}
