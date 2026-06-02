package keychain

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// SetAllowedCallsSelector is the function selector for
// setAllowedCalls(address,(address,(bytes4,address[])[])[]).
const SetAllowedCallsSelector = "0xf5456703"

// RemoveAllowedCallsSelector is the function selector for
// removeAllowedCalls(address,address).
const RemoveAllowedCallsSelector = "0xf3941811"

// AuthorizeKeyWithWitnessSelector is the function selector for the T5
// authorizeKey(address,uint8,KeyRestrictions,bytes32) overload.
const AuthorizeKeyWithWitnessSelector = "0xe3c154d2"

// BurnKeyAuthorizationWitnessSelector is the function selector for
// burnKeyAuthorizationWitness(bytes32).
const BurnKeyAuthorizationWitnessSelector = "0xcff31c46"

// IsKeyAuthorizationWitnessBurnedSelector is the function selector for
// isKeyAuthorizationWitnessBurned(address,bytes32).
const IsKeyAuthorizationWitnessBurnedSelector = "0x8e6c7e11"

// SignatureType constants matching the Rust/Solidity enum.
const (
	SignatureTypeSecp256k1 = 0
	SignatureTypeP256      = 1
	SignatureTypeWebAuthn  = 2
)

// abiSelectorRule is the Go struct that matches the ABI tuple encoding.
type abiSelectorRule struct {
	Selector   [4]byte          `abi:"selector"`
	Recipients []common.Address `abi:"recipients"`
}

// abiCallScope is the Go struct that matches the ABI tuple encoding.
type abiCallScope struct {
	Target        common.Address    `abi:"target"`
	SelectorRules []abiSelectorRule `abi:"selectorRules"`
}

// abiTokenLimit matches the ABI tuple (address, uint256, uint64).
type abiTokenLimit struct {
	Token  common.Address `abi:"token"`
	Amount *big.Int       `abi:"amount"`
	Period uint64         `abi:"period"`
}

// abiKeyRestrictions matches the ABI tuple for KeyRestrictions.
type abiKeyRestrictions struct {
	Expiry        uint64          `abi:"expiry"`
	EnforceLimits bool            `abi:"enforceLimits"`
	Limits        []abiTokenLimit `abi:"limits"`
	AllowAnyCalls bool            `abi:"allowAnyCalls"`
	AllowedCalls  []abiCallScope  `abi:"allowedCalls"`
}

func toABICallScopes(scopes []CallScope) []abiCallScope {
	result := make([]abiCallScope, len(scopes))
	for i, s := range scopes {
		rules := make([]abiSelectorRule, len(s.SelectorRules))
		for j, r := range s.SelectorRules {
			recipients := make([]common.Address, len(r.Recipients))
			copy(recipients, r.Recipients)
			rules[j] = abiSelectorRule{
				Selector:   r.Selector,
				Recipients: recipients,
			}
		}
		result[i] = abiCallScope{
			Target:        s.Target,
			SelectorRules: rules,
		}
	}
	return result
}

// Call represents an EVM call with target address and calldata.
type Call struct {
	To   common.Address
	Data []byte
}

// keychainAddress is the precompile address.
var keychainAddress = common.HexToAddress(AccountKeychainAddress)

// authorizeKeyABI is the parsed ABI for authorizeKey(address,uint8,KeyRestrictions).
var authorizeKeyABI abi.ABI

// authorizeKeyWithWitnessABI is the parsed ABI for authorizeKey(address,uint8,KeyRestrictions,bytes32).
var authorizeKeyWithWitnessABI abi.ABI

// setAllowedCallsABI is the parsed ABI for setAllowedCalls(address,CallScope[]).
var setAllowedCallsABI abi.ABI

// removeAllowedCallsABI is the parsed ABI for removeAllowedCalls(address,address).
var removeAllowedCallsABI abi.ABI

// burnKeyAuthorizationWitnessABI is the parsed ABI for burnKeyAuthorizationWitness(bytes32).
var burnKeyAuthorizationWitnessABI abi.ABI

// isKeyAuthorizationWitnessBurnedABI is the parsed ABI for isKeyAuthorizationWitnessBurned(address,bytes32).
var isKeyAuthorizationWitnessBurnedABI abi.ABI

// revokeKeyABI is the parsed ABI for revokeKey(address).
var revokeKeyABI abi.ABI

// updateSpendingLimitABI is the parsed ABI for updateSpendingLimit(address,address,uint256).
var updateSpendingLimitABI abi.ABI

func mustParseABI(json string) abi.ABI {
	parsed, err := abi.JSON(strings.NewReader(json))
	if err != nil {
		panic(fmt.Sprintf("failed to parse ABI: %v", err))
	}
	return parsed
}

func init() {
	authorizeKeyABI = mustParseABI(`[{
		"name": "authorizeKey",
		"type": "function",
		"inputs": [
			{"name": "keyId", "type": "address"},
			{"name": "signatureType", "type": "uint8"},
			{"name": "restrictions", "type": "tuple", "components": [
				{"name": "expiry", "type": "uint64"},
				{"name": "enforceLimits", "type": "bool"},
				{"name": "limits", "type": "tuple[]", "components": [
					{"name": "token", "type": "address"},
					{"name": "amount", "type": "uint256"},
					{"name": "period", "type": "uint64"}
				]},
				{"name": "allowAnyCalls", "type": "bool"},
				{"name": "allowedCalls", "type": "tuple[]", "components": [
					{"name": "target", "type": "address"},
					{"name": "selectorRules", "type": "tuple[]", "components": [
						{"name": "selector", "type": "bytes4"},
						{"name": "recipients", "type": "address[]"}
					]}
				]}
			]}
		]
	}]`)

	authorizeKeyWithWitnessABI = mustParseABI(`[{
		"name": "authorizeKey",
		"type": "function",
		"inputs": [
			{"name": "keyId", "type": "address"},
			{"name": "signatureType", "type": "uint8"},
			{"name": "restrictions", "type": "tuple", "components": [
				{"name": "expiry", "type": "uint64"},
				{"name": "enforceLimits", "type": "bool"},
				{"name": "limits", "type": "tuple[]", "components": [
					{"name": "token", "type": "address"},
					{"name": "amount", "type": "uint256"},
					{"name": "period", "type": "uint64"}
				]},
				{"name": "allowAnyCalls", "type": "bool"},
				{"name": "allowedCalls", "type": "tuple[]", "components": [
					{"name": "target", "type": "address"},
					{"name": "selectorRules", "type": "tuple[]", "components": [
						{"name": "selector", "type": "bytes4"},
						{"name": "recipients", "type": "address[]"}
					]}
				]}
			]},
			{"name": "witness", "type": "bytes32"}
		]
	}]`)

	setAllowedCallsABI = mustParseABI(`[{
		"name": "setAllowedCalls",
		"type": "function",
		"inputs": [
			{"name": "keyId", "type": "address"},
			{"name": "scopes", "type": "tuple[]", "components": [
				{"name": "target", "type": "address"},
				{"name": "selectorRules", "type": "tuple[]", "components": [
					{"name": "selector", "type": "bytes4"},
					{"name": "recipients", "type": "address[]"}
				]}
			]}
		]
	}]`)

	removeAllowedCallsABI = mustParseABI(`[{
		"name": "removeAllowedCalls",
		"type": "function",
		"inputs": [
			{"name": "keyId", "type": "address"},
			{"name": "target", "type": "address"}
		]
	}]`)

	burnKeyAuthorizationWitnessABI = mustParseABI(`[{
		"name": "burnKeyAuthorizationWitness",
		"type": "function",
		"inputs": [
			{"name": "witness", "type": "bytes32"}
		]
	}]`)

	isKeyAuthorizationWitnessBurnedABI = mustParseABI(`[{
		"name": "isKeyAuthorizationWitnessBurned",
		"type": "function",
		"inputs": [
			{"name": "account", "type": "address"},
			{"name": "witness", "type": "bytes32"}
		]
	}]`)

	revokeKeyABI = mustParseABI(`[{
		"name": "revokeKey",
		"type": "function",
		"inputs": [
			{"name": "keyId", "type": "address"}
		]
	}]`)

	updateSpendingLimitABI = mustParseABI(`[{
		"name": "updateSpendingLimit",
		"type": "function",
		"inputs": [
			{"name": "keyId", "type": "address"},
			{"name": "token", "type": "address"},
			{"name": "newLimit", "type": "uint256"}
		]
	}]`)
}

func toABIKeyRestrictions(restrictions *KeyRestrictions) (abiKeyRestrictions, error) {
	if restrictions == nil {
		return abiKeyRestrictions{}, fmt.Errorf("restrictions must not be nil")
	}
	if err := restrictions.Validate(); err != nil {
		return abiKeyRestrictions{}, fmt.Errorf("invalid restrictions: %w", err)
	}

	limits := make([]abiTokenLimit, len(restrictions.limits))
	for i, l := range restrictions.limits {
		limits[i] = abiTokenLimit{
			Token:  l.Token,
			Amount: l.Amount,
			Period: l.Period,
		}
	}

	return abiKeyRestrictions{
		Expiry:        restrictions.expiry,
		EnforceLimits: restrictions.enforceLimits,
		Limits:        limits,
		AllowAnyCalls: restrictions.allowAnyCalls,
		AllowedCalls:  toABICallScopes(restrictions.allowedCalls),
	}, nil
}

// AuthorizeKey builds an authorizeKey(address,uint8,KeyRestrictions) call.
func AuthorizeKey(keyID common.Address, signatureType uint8, restrictions *KeyRestrictions) (Call, error) {
	r, err := toABIKeyRestrictions(restrictions)
	if err != nil {
		return Call{}, err
	}

	data, err := authorizeKeyABI.Pack("authorizeKey", keyID, signatureType, r)
	if err != nil {
		return Call{}, fmt.Errorf("failed to encode authorizeKey: %w", err)
	}
	return Call{To: keychainAddress, Data: data}, nil
}

// AuthorizeKeyWithWitness builds an authorizeKey(address,uint8,KeyRestrictions,bytes32) call.
func AuthorizeKeyWithWitness(keyID common.Address, signatureType uint8, restrictions *KeyRestrictions, witness common.Hash) (Call, error) {
	r, err := toABIKeyRestrictions(restrictions)
	if err != nil {
		return Call{}, err
	}

	data, err := authorizeKeyWithWitnessABI.Pack("authorizeKey", keyID, signatureType, r, witness)
	if err != nil {
		return Call{}, fmt.Errorf("failed to encode authorizeKey with witness: %w", err)
	}
	return Call{To: keychainAddress, Data: data}, nil
}

// BurnKeyAuthorizationWitness builds a burnKeyAuthorizationWitness(bytes32) call.
func BurnKeyAuthorizationWitness(witness common.Hash) (Call, error) {
	data, err := burnKeyAuthorizationWitnessABI.Pack("burnKeyAuthorizationWitness", witness)
	if err != nil {
		return Call{}, fmt.Errorf("failed to encode burnKeyAuthorizationWitness: %w", err)
	}
	return Call{To: keychainAddress, Data: data}, nil
}

// IsKeyAuthorizationWitnessBurned builds an isKeyAuthorizationWitnessBurned(address,bytes32) call.
func IsKeyAuthorizationWitnessBurned(account common.Address, witness common.Hash) (Call, error) {
	data, err := isKeyAuthorizationWitnessBurnedABI.Pack("isKeyAuthorizationWitnessBurned", account, witness)
	if err != nil {
		return Call{}, fmt.Errorf("failed to encode isKeyAuthorizationWitnessBurned: %w", err)
	}
	return Call{To: keychainAddress, Data: data}, nil
}

// RevokeKey builds a revokeKey(address) call.
func RevokeKey(keyID common.Address) (Call, error) {
	data, err := revokeKeyABI.Pack("revokeKey", keyID)
	if err != nil {
		return Call{}, fmt.Errorf("failed to encode revokeKey: %w", err)
	}
	return Call{To: keychainAddress, Data: data}, nil
}

// SetAllowedCalls builds a setAllowedCalls(address,CallScope[]) call.
func SetAllowedCalls(keyID common.Address, scopes []CallScope) (Call, error) {
	data, err := setAllowedCallsABI.Pack("setAllowedCalls", keyID, toABICallScopes(scopes))
	if err != nil {
		return Call{}, fmt.Errorf("failed to encode setAllowedCalls: %w", err)
	}
	return Call{To: keychainAddress, Data: data}, nil
}

// RemoveAllowedCalls builds a removeAllowedCalls(address,address) call.
func RemoveAllowedCalls(keyID common.Address, target common.Address) (Call, error) {
	data, err := removeAllowedCallsABI.Pack("removeAllowedCalls", keyID, target)
	if err != nil {
		return Call{}, fmt.Errorf("failed to encode removeAllowedCalls: %w", err)
	}
	return Call{To: keychainAddress, Data: data}, nil
}

// UpdateSpendingLimit builds an updateSpendingLimit(address,address,uint256) call.
func UpdateSpendingLimit(keyID common.Address, token common.Address, newLimit *big.Int) (Call, error) {
	data, err := updateSpendingLimitABI.Pack("updateSpendingLimit", keyID, token, newLimit)
	if err != nil {
		return Call{}, fmt.Errorf("failed to encode updateSpendingLimit: %w", err)
	}
	return Call{To: keychainAddress, Data: data}, nil
}
