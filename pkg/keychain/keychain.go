package keychain

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tempoxyz/tempo-go/pkg/signer"
	"github.com/tempoxyz/tempo-go/pkg/transaction"
)

const (
	// KeychainSignatureType is the Keychain V2 signature type identifier.
	KeychainSignatureType = 0x04

	// InnerSignatureLength is the length of the inner secp256k1 signature (r + s + v).
	InnerSignatureLength = 65

	// KeychainSignatureLength is the total length of a Keychain signature.
	// Format: type (1) + root_account (20) + inner_signature (65) = 86 bytes.
	KeychainSignatureLength = 86

	// AccountKeychainAddress is the address of the AccountKeychain precompile.
	AccountKeychainAddress = "0xAAAAAAAA00000000000000000000000000000000"
)

// BuildKeychainSignature creates a Keychain V2 signature from an inner secp256k1 signature.
//
// The Keychain V2 signature format is:
//
//	0x04 || root_account (20 bytes) || inner_signature (65 bytes)
//
// Parameters:
//   - innerSig: The secp256k1 signature from the access key
//   - rootAccount: The address of the root account (the account the access key acts on behalf of)
//
// Returns the 86-byte Keychain signature.
func BuildKeychainSignature(innerSig *signer.Signature, rootAccount common.Address) []byte {
	result := make([]byte, KeychainSignatureLength)

	// Byte 0: Keychain V2 signature type (0x04)
	result[0] = KeychainSignatureType

	// Bytes 1-20: Root account address
	copy(result[1:21], rootAccount.Bytes())

	// Bytes 21-85: Inner signature (r || s || v)
	// R: 32 bytes
	rBytes := innerSig.R.Bytes()
	copy(result[21+(32-len(rBytes)):53], rBytes)

	// S: 32 bytes
	sBytes := innerSig.S.Bytes()
	copy(result[53+(32-len(sBytes)):85], sBytes)

	// V: 1 byte (yParity)
	result[85] = innerSig.YParity

	return result
}

// SignWithAccessKey signs a Tempo transaction using an access key.
//
// This creates a Keychain V2 signature that allows the access key to sign
// transactions on behalf of the root account.
//
// The access key signs keccak256(0x04 || sig_hash || user_address) instead of
// the raw sig_hash, providing domain separation.
//
// The function:
//  1. Sets tx.From to the root account address
//  2. Computes the signing hash
//  3. Signs keccak256(0x04 || sig_hash || root_account) with the access key
//  4. Wraps the signature in Keychain format (0x04 || root || inner_sig)
//
// Parameters:
//   - tx: The transaction to sign (will be modified in place)
//   - accessKeySigner: The signer for the access key
//   - rootAccount: The address of the root account
//
// Returns an error if signing fails.
func SignWithAccessKey(tx *transaction.Tx, accessKeySigner *signer.Signer, rootAccount common.Address) error {
	// Validate transaction before signing
	if err := tx.Validate(); err != nil {
		return err
	}

	// Set the from address to the root account BEFORE computing signing hash
	tx.From = rootAccount

	// Get the signing hash
	sigHash, err := transaction.GetSignPayload(tx)
	if err != nil {
		return fmt.Errorf("failed to get sign payload: %w", err)
	}

	// Compute V2 signing hash: keccak256(0x04 || sig_hash || root_account)
	v2Input := make([]byte, 0, 1+32+20)
	v2Input = append(v2Input, KeychainSignatureType)
	v2Input = append(v2Input, sigHash.Bytes()...)
	v2Input = append(v2Input, rootAccount.Bytes()...)
	signingHash := crypto.Keccak256Hash(v2Input)

	// Sign with the access key
	innerSig, err := accessKeySigner.Sign(signingHash)
	if err != nil {
		return fmt.Errorf("failed to sign with access key: %w", err)
	}

	// Build the Keychain signature
	keychainSig := BuildKeychainSignature(innerSig, rootAccount)

	// Create a signature envelope with the raw Keychain signature bytes
	tx.Signature = &signer.SignatureEnvelope{
		Type: "keychain",
		Raw:  keychainSig,
	}

	return nil
}

// ParseKeychainSignature parses a Keychain signature into its components.
//
// Returns the signature type, root account address, and inner signature.
// Returns an error if the signature is invalid.
func ParseKeychainSignature(sig []byte) (sigType byte, rootAccount common.Address, innerSig *signer.Signature, err error) {
	if len(sig) != KeychainSignatureLength {
		return 0, common.Address{}, nil, fmt.Errorf("invalid keychain signature length: expected %d, got %d", KeychainSignatureLength, len(sig))
	}

	sigType = sig[0]
	if sigType != KeychainSignatureType {
		return 0, common.Address{}, nil, fmt.Errorf("invalid keychain signature type: expected 0x%02x, got 0x%02x", KeychainSignatureType, sigType)
	}

	rootAccount = common.BytesToAddress(sig[1:21])

	innerSig = signer.NewSignature(
		byteSliceToBigInt(sig[21:53]), // R
		byteSliceToBigInt(sig[53:85]), // S
		sig[85],                       // YParity
	)

	return sigType, rootAccount, innerSig, nil
}

// VerifyAccessKeySignature verifies that a Keychain signature was created by a valid access key.
//
// Parameters:
//   - tx: The transaction with the Keychain signature
//
// Returns the access key address (the signer) and root account address if valid.
func VerifyAccessKeySignature(tx *transaction.Tx) (accessKeyAddr, rootAccount common.Address, err error) {
	if tx.Signature == nil {
		return common.Address{}, common.Address{}, fmt.Errorf("transaction has no signature")
	}

	if tx.Signature.Type != "keychain" || tx.Signature.Raw == nil {
		return common.Address{}, common.Address{}, fmt.Errorf("signature is not a keychain signature")
	}

	_, rootAccount, innerSig, err := ParseKeychainSignature(tx.Signature.Raw)
	if err != nil {
		return common.Address{}, common.Address{}, fmt.Errorf("failed to parse keychain signature: %w", err)
	}

	// Get the signing hash (with From set to root account)
	txCopy := *tx
	txCopy.From = rootAccount
	txCopy.Signature = nil

	sigHash, err := transaction.GetSignPayload(&txCopy)
	if err != nil {
		return common.Address{}, common.Address{}, fmt.Errorf("failed to get sign payload: %w", err)
	}

	// Compute V2 signing hash: keccak256(0x04 || sig_hash || root_account)
	v2Input := make([]byte, 0, 1+32+20)
	v2Input = append(v2Input, KeychainSignatureType)
	v2Input = append(v2Input, sigHash.Bytes()...)
	v2Input = append(v2Input, rootAccount.Bytes()...)
	signingHash := crypto.Keccak256Hash(v2Input)

	// Recover the access key address from the inner signature
	accessKeyAddr, err = signer.RecoverAddress(signingHash, innerSig)
	if err != nil {
		return common.Address{}, common.Address{}, fmt.Errorf("failed to recover access key address: %w", err)
	}

	return accessKeyAddr, rootAccount, nil
}
