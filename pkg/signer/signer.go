package signer

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

// Signer is a basic wrapper for managing ECDSA private key and provides signing functionality.
type Signer struct {
	privateKey *ecdsa.PrivateKey
	address    common.Address
}

// NewSigner creates a new signer from a hex-encoded private key.
func NewSigner(privateKeyHex string) (*Signer, error) {
	if !strings.HasPrefix(privateKeyHex, "0x") {
		privateKeyHex = "0x" + privateKeyHex
	}

	privateKeyBytes, err := hexutil.Decode(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode: %v", ErrInvalidPrivateKey, err)
	}

	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse: %v", ErrInvalidPrivateKey, err)
	}

	address := crypto.PubkeyToAddress(privateKey.PublicKey)

	return &Signer{
		privateKey: privateKey,
		address:    address,
	}, nil
}

// NewSignerFromKey creates a new signer from an existing ECDSA private key.
func NewSignerFromKey(privateKey *ecdsa.PrivateKey) *Signer {
	address := crypto.PubkeyToAddress(privateKey.PublicKey)
	return &Signer{
		privateKey: privateKey,
		address:    address,
	}
}

// Address returns the Ethereum address for this signer.
func (s *Signer) Address() common.Address {
	return s.address
}

// PrivateKey returns the underlying ECDSA private key.
func (s *Signer) PrivateKey() *ecdsa.PrivateKey {
	return s.privateKey
}

// Sign signs a hash with the signer's private key.
// Returns a Signature with R, S, and YParity components.
func (s *Signer) Sign(hash common.Hash) (*Signature, error) {
	sigBytes, err := crypto.Sign(hash.Bytes(), s.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	r := new(big.Int).SetBytes(sigBytes[:32])
	sigS := new(big.Int).SetBytes(sigBytes[32:64])
	yParity := sigBytes[64] // Always 0 or 1 from crypto.Sign

	return NewSignature(r, sigS, yParity), nil
}

// SignData signs arbitrary data by first hashing it with Keccak256.
func (s *Signer) SignData(data []byte) (*Signature, error) {
	hash := crypto.Keccak256Hash(data)
	return s.Sign(hash)
}

// maxScalarBytes is the maximum byte length for secp256k1 scalar values (R and S).
// Scalars must fit within 32 bytes (256 bits) to be valid signature components.
const maxScalarBytes = 32

// RecoverAddress recovers the address that signed the given hash with the given signature.
func RecoverAddress(hash common.Hash, sig *Signature) (common.Address, error) {
	if sig == nil {
		return common.Address{}, fmt.Errorf("%w: signature is nil", ErrInvalidSignature)
	}
	if sig.R == nil || sig.S == nil {
		return common.Address{}, fmt.Errorf("%w: R or S is nil", ErrInvalidSignature)
	}

	rBytes := sig.R.Bytes()
	if len(rBytes) > maxScalarBytes {
		return common.Address{}, fmt.Errorf("%w: R exceeds %d bytes (got %d)", ErrInvalidSignature, maxScalarBytes, len(rBytes))
	}
	sBytes := sig.S.Bytes()
	if len(sBytes) > maxScalarBytes {
		return common.Address{}, fmt.Errorf("%w: S exceeds %d bytes (got %d)", ErrInvalidSignature, maxScalarBytes, len(sBytes))
	}

	sigBytes := make([]byte, 65)
	sig.R.FillBytes(sigBytes[0:32])
	sig.S.FillBytes(sigBytes[32:64])
	sigBytes[64] = sig.YParity // crypto.SigToPub expects 0 or 1

	pubkey, err := crypto.SigToPub(hash.Bytes(), sigBytes)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to recover public key: %w", err)
	}

	return crypto.PubkeyToAddress(*pubkey), nil
}

// VerifySignature verifies that the given signature was created by this signer.
func (s *Signer) VerifySignature(hash common.Hash, sig *Signature) (bool, error) {
	recoveredAddress, err := RecoverAddress(hash, sig)
	if err != nil {
		return false, err
	}

	return recoveredAddress == s.address, nil
}

// Signature represents an ECDSA signature.
type Signature struct {
	R       *big.Int `json:"r"`
	S       *big.Int `json:"s"`
	YParity uint8    `json:"yParity"` // Recovery ID: 0 or 1
}

// V returns the legacy V value (27 or 28) for backwards compatibility.
func (s *Signature) V() uint8 {
	return 27 + s.YParity
}

// SignatureEnvelope wraps a signature with its type.
// Supports secp256k1, p256, and webauthn signatures.
type SignatureEnvelope struct {
	Type      string     `json:"type"`      // "secp256k1", "p256", or "webauthn"
	Signature *Signature `json:"signature"` // The actual signature
}

// NewSignature creates a new ECDSA signature.
func NewSignature(r, s *big.Int, yParity uint8) *Signature {
	return &Signature{R: r, S: s, YParity: yParity}
}

// NewSignatureEnvelope creates a new signature envelope with secp256k1 type.
func NewSignatureEnvelope(r, s *big.Int, yParity uint8) *SignatureEnvelope {
	return &SignatureEnvelope{
		Type:      "secp256k1",
		Signature: NewSignature(r, s, yParity),
	}
}
