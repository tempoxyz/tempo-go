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

var secp256k1HalfN = new(big.Int).Rsh(new(big.Int).Set(crypto.S256().Params().N), 1)

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
	if sig.S.Cmp(secp256k1HalfN) > 0 {
		return common.Address{}, fmt.Errorf("%w: S value is not Low-S (EIP-2)", ErrInvalidSignature)
	}
	if !crypto.ValidateSignatureValues(sig.YParity, sig.R, sig.S, true) {
		return common.Address{}, fmt.Errorf("%w: invalid signature values", ErrInvalidSignature)
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

// SignatureLength is the size of a canonical secp256k1 wire signature (r || s || v).
const SignatureLength = 65

// ParseRecoveryID maps a wire recovery byte to a 0/1 YParity. Both the raw
// parity (0/1) and the legacy form (27/28) are accepted.
func ParseRecoveryID(recoveryID byte) (uint8, error) {
	switch recoveryID {
	case 0, 1:
		return recoveryID, nil
	case 27, 28:
		return recoveryID - 27, nil
	default:
		return 0, fmt.Errorf("%w: recovery id must be 0, 1, 27, or 28, got %d", ErrInvalidSignature, recoveryID)
	}
}

// Bytes returns the canonical 65-byte wire form r || s || v, where v is the
// legacy recovery ID (27/28) used by Rust's alloy signatures. It validates that
// R and S are non-nil, non-negative 256-bit scalars and that YParity is 0 or 1.
func (s *Signature) Bytes() ([]byte, error) {
	if s == nil || s.R == nil || s.S == nil {
		return nil, fmt.Errorf("%w: signature and its R/S components must be non-nil", ErrInvalidSignature)
	}
	if s.R.Sign() < 0 || s.S.Sign() < 0 {
		return nil, fmt.Errorf("%w: R and S must be non-negative", ErrInvalidSignature)
	}
	if l := len(s.R.Bytes()); l > maxScalarBytes {
		return nil, fmt.Errorf("%w: R exceeds %d bytes (got %d)", ErrInvalidSignature, maxScalarBytes, l)
	}
	if l := len(s.S.Bytes()); l > maxScalarBytes {
		return nil, fmt.Errorf("%w: S exceeds %d bytes (got %d)", ErrInvalidSignature, maxScalarBytes, l)
	}
	if s.YParity > 1 {
		return nil, fmt.Errorf("%w: invalid yParity: must be 0 or 1, got %d", ErrInvalidSignature, s.YParity)
	}
	out := make([]byte, SignatureLength)
	s.R.FillBytes(out[0:32])
	s.S.FillBytes(out[32:64])
	out[64] = s.V()
	return out, nil
}

// ParseSignatureBytes decodes a 65-byte wire signature r || s || v into the
// public model, accepting either 0/1 or 27/28 for v.
func ParseSignatureBytes(b []byte) (*Signature, error) {
	if len(b) != SignatureLength {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidSignature, SignatureLength, len(b))
	}
	yParity, err := ParseRecoveryID(b[64])
	if err != nil {
		return nil, err
	}
	return NewSignature(new(big.Int).SetBytes(b[0:32]), new(big.Int).SetBytes(b[32:64]), yParity), nil
}

// Clone returns a deep copy of the signature.
func (s *Signature) Clone() *Signature {
	if s == nil {
		return nil
	}
	clone := *s
	if s.R != nil {
		clone.R = new(big.Int).Set(s.R)
	}
	if s.S != nil {
		clone.S = new(big.Int).Set(s.S)
	}
	return &clone
}

// Clone returns a deep copy of the envelope.
func (e *SignatureEnvelope) Clone() *SignatureEnvelope {
	if e == nil {
		return nil
	}
	clone := *e
	clone.Signature = e.Signature.Clone()
	if e.Raw != nil {
		clone.Raw = append([]byte(nil), e.Raw...)
	}
	return &clone
}

// SignatureEnvelope wraps a signature with its type.
// Supports secp256k1, p256, webauthn, and keychain signatures.
type SignatureEnvelope struct {
	Type      string     `json:"type"`      // "secp256k1", "p256", "webauthn", or "keychain"
	Signature *Signature `json:"signature"` // The actual signature (for secp256k1, p256, webauthn)
	Raw       []byte     `json:"raw"`       // Raw signature bytes (for keychain signatures)
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
