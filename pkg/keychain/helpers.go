package keychain

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

// GetRemainingLimitSelector is the function selector for getRemainingLimit(address,address,address).
const GetRemainingLimitSelector = "0x63b4290d"

// byteSliceToBigInt converts a byte slice to a big.Int.
func byteSliceToBigInt(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}

// EncodeGetRemainingLimitCalldata encodes the calldata for getRemainingLimit(address,address,address).
//
// Parameters:
//   - accountAddress: The root wallet address
//   - keyID: The access key ID (address)
//   - tokenAddress: The token to check limit for
//
// Returns the hex-encoded calldata (with 0x prefix).
func EncodeGetRemainingLimitCalldata(accountAddress, keyID, tokenAddress common.Address) string {
	accountPadded := padAddress(accountAddress)
	keyPadded := padAddress(keyID)
	tokenPadded := padAddress(tokenAddress)

	return GetRemainingLimitSelector + accountPadded + keyPadded + tokenPadded
}

// padAddress pads an address to 32 bytes (64 hex chars) for ABI encoding.
func padAddress(addr common.Address) string {
	return strings.Repeat("0", 24) + strings.ToLower(hex.EncodeToString(addr.Bytes()))
}

// ParseRemainingLimitResult parses the result of a getRemainingLimit call.
//
// The result is a 32-byte big-endian uint256.
func ParseRemainingLimitResult(result []byte) *big.Int {
	if len(result) == 0 {
		return big.NewInt(0)
	}
	return new(big.Int).SetBytes(result)
}

// IsKeychainSignature checks if the given signature bytes represent a Keychain signature.
func IsKeychainSignature(sig []byte) bool {
	return len(sig) == KeychainSignatureLength && sig[0] == KeychainSignatureType
}

// GetKeychainAddress returns the AccountKeychain precompile address.
func GetKeychainAddress() common.Address {
	return common.HexToAddress(AccountKeychainAddress)
}

// AuthorizeKeySelector is the function selector for the legacy (pre-T3)
// authorizeKey(address,uint8,uint64,bool,(address,uint256)[]).
const AuthorizeKeySelector = "0x54063a55"

// AuthorizeKeyT3Selector is the function selector for the T3+
// authorizeKey(address,uint8,(uint64,bool,(address,uint256,uint64)[],bool,(address,(bytes4,address[])[])[]))
const AuthorizeKeyT3Selector = "0x980a6025"

// RevokeKeySelector is the function selector for revokeKey(address).
const RevokeKeySelector = "0x5ae7ab32"

// UpdateSpendingLimitSelector is the function selector for updateSpendingLimit(address,address,uint256).
const UpdateSpendingLimitSelector = "0xcbbb4480"

// GetKeySelector is the function selector for getKey(address,address).
const GetKeySelector = "0xbc298553"

// GetTransactionKeySelector is the function selector for getTransactionKey().
const GetTransactionKeySelector = "0xb07fbc1a"

// SpendingLimit represents a per-token spending limit for an access key.
type SpendingLimit struct {
	Token  common.Address
	Amount *big.Int
}

// AuthorizedKey represents an authorized access key with its configuration.
type AuthorizedKey struct {
	KeyID         common.Address
	SignatureType uint8 // 0 = Secp256k1, 1 = P256, 2 = WebAuthn
	Expiry        uint64
	EnforceLimits bool
	IsRevoked     bool
}

// ValidateAccessKeySignature is a helper that validates a signature is a proper keychain signature.
func ValidateAccessKeySignature(sig []byte) error {
	if len(sig) != KeychainSignatureLength {
		return fmt.Errorf("invalid signature length: expected %d, got %d", KeychainSignatureLength, len(sig))
	}
	if sig[0] != KeychainSignatureType {
		return fmt.Errorf("invalid signature type: expected 0x%02x, got 0x%02x", KeychainSignatureType, sig[0])
	}
	return nil
}
