package keychain

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/tempoxyz/tempo-go/pkg/signer"
	"github.com/tempoxyz/tempo-go/pkg/transaction"
)

// secp256k1SignatureLength is the byte length of a secp256k1 signature (r || s || v).
const secp256k1SignatureLength = 65

// KeyAuthorization is a tx-embedded key authorization (TIP-1049). It lets a root
// or admin key authorize another key inside a transaction, rather than via a
// separate AccountKeychain precompile call.
//
// Optional fields use nil/zero to mean "absent":
//   - Expiry == 0 means the key never expires.
//   - Limits == nil means unlimited spending; a non-nil empty slice means no spending.
//   - AllowedCalls == nil means unrestricted calls; a non-nil empty slice means deny all.
//   - Witness == nil means no witness; a non-nil value (including zero) attaches one.
//   - Account == nil means the field is omitted.
type KeyAuthorization struct {
	ChainID      uint64
	KeyType      uint8
	KeyID        common.Address
	Expiry       uint64
	Limits       *[]TokenLimit
	AllowedCalls *[]CallScope
	Witness      *common.Hash
	IsAdmin      bool
	Account      *common.Address
}

// NewKeyAuthorization creates an unrestricted key authorization (no expiry,
// limits, or call scopes).
func NewKeyAuthorization(chainID uint64, keyType uint8, keyID common.Address) *KeyAuthorization {
	return &KeyAuthorization{ChainID: chainID, KeyType: keyType, KeyID: keyID}
}

// WithExpiry sets an expiry timestamp. Zero means the key never expires.
func (a *KeyAuthorization) WithExpiry(expiry uint64) *KeyAuthorization {
	a.Expiry = expiry
	return a
}

// WithLimits sets token spending limits.
func (a *KeyAuthorization) WithLimits(limits []TokenLimit) *KeyAuthorization {
	a.Limits = &limits
	return a
}

// WithNoSpending denies all spending (limits enforced with an empty allowlist).
func (a *KeyAuthorization) WithNoSpending() *KeyAuthorization {
	empty := []TokenLimit{}
	a.Limits = &empty
	return a
}

// WithAllowedCalls sets call-scope restrictions.
func (a *KeyAuthorization) WithAllowedCalls(scopes []CallScope) *KeyAuthorization {
	a.AllowedCalls = &scopes
	return a
}

// WithNoCalls denies all calls (scoped mode with an empty allowlist).
func (a *KeyAuthorization) WithNoCalls() *KeyAuthorization {
	empty := []CallScope{}
	a.AllowedCalls = &empty
	return a
}

// WithWitness attaches a TIP-1053 witness (zero is a valid value).
func (a *KeyAuthorization) WithWitness(witness common.Hash) *KeyAuthorization {
	a.Witness = &witness
	return a
}

// IntoAdmin makes this an admin-key authorization bound to account. Admin keys
// carry no expiry, limits, or call scopes.
func (a *KeyAuthorization) IntoAdmin(account common.Address) *KeyAuthorization {
	a.IsAdmin = true
	a.Account = &account
	return a
}

// WithAccount binds this authorization to a target account without making the
// key an admin key.
func (a *KeyAuthorization) WithAccount(account common.Address) *KeyAuthorization {
	a.Account = &account
	return a
}

// Validate checks for conflicting settings.
func (a *KeyAuthorization) Validate() error {
	if a.KeyType > SignatureTypeWebAuthn {
		return fmt.Errorf("invalid key type: %d", a.KeyType)
	}
	if a.IsAdmin && (a.Expiry != 0 || a.Limits != nil || a.AllowedCalls != nil) {
		return fmt.Errorf("admin keys cannot have expiry, limits, or allowed calls")
	}
	if a.IsAdmin && a.Account == nil {
		return fmt.Errorf("authorizations that create admin keys must set Account")
	}
	if a.Limits != nil {
		for i, l := range *a.Limits {
			if l.Amount == nil {
				return fmt.Errorf("limits[%d].amount must not be nil", i)
			}
			if l.Amount.Sign() < 0 {
				return fmt.Errorf("limits[%d].amount must be non-negative", i)
			}
			if l.Amount.BitLen() > 256 {
				return fmt.Errorf("limits[%d].amount exceeds uint256", i)
			}
		}
	}
	return nil
}

// encodeFields builds the RLP field list for the unsigned authorization.
//
// The first three fields are always present. The trailing optional fields are
// encoded canonically: trailing absent fields are omitted, but an absent field
// that precedes a present one is encoded as an empty placeholder (0x80).
func (a *KeyAuthorization) encodeFields() ([]interface{}, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}

	fields := []interface{}{
		u64ToBytes(a.ChainID),
		u64ToBytes(uint64(a.KeyType)),
		a.KeyID.Bytes(),
	}

	var witnessVal interface{} = []byte{}
	if a.Witness != nil {
		witnessVal = a.Witness.Bytes()
	}
	var accountVal interface{} = []byte{}
	if a.Account != nil {
		accountVal = a.Account.Bytes()
	}

	optionals := []struct {
		present bool
		value   interface{}
	}{
		{a.Expiry != 0, u64ToBytes(a.Expiry)},
		{a.Limits != nil, encodeTokenLimits(a.Limits)},
		{a.AllowedCalls != nil, encodeCallScopes(a.AllowedCalls)},
		{a.Witness != nil, witnessVal},
		{a.IsAdmin, []byte{0x01}},
		{a.Account != nil, accountVal},
	}

	highest := -1
	for i, o := range optionals {
		if o.present {
			highest = i
		}
	}

	for i := 0; i <= highest; i++ {
		if optionals[i].present {
			fields = append(fields, optionals[i].value)
		} else {
			// Empty placeholder (0x80) keeps later fields in position.
			fields = append(fields, []byte{})
		}
	}

	return fields, nil
}

// SignatureHash returns keccak256(rlp(authorization)), the hash the root or
// admin key signs.
func (a *KeyAuthorization) SignatureHash() (common.Hash, error) {
	fields, err := a.encodeFields()
	if err != nil {
		return common.Hash{}, err
	}
	encoded, err := rlp.EncodeToBytes(fields)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to rlp encode key authorization: %w", err)
	}
	return crypto.Keccak256Hash(encoded), nil
}

// Sign signs the authorization with a secp256k1 key and returns the signed
// key authorization value to assign to tx.KeyAuthorization.
func (a *KeyAuthorization) Sign(s *signer.Signer) ([]interface{}, error) {
	hash, err := a.SignatureHash()
	if err != nil {
		return nil, err
	}
	sig, err := s.Sign(hash)
	if err != nil {
		return nil, fmt.Errorf("failed to sign key authorization: %w", err)
	}

	sigBytes, err := sig.Bytes()
	if err != nil {
		return nil, fmt.Errorf("failed to sign key authorization: %w", err)
	}

	return a.BuildSigned(sigBytes)
}

// BuildSigned wraps the authorization with a pre-computed primitive signature.
//
// Use this for P256 or WebAuthn signatures, where signature is the raw primitive
// signature bytes (with their type prefix). For secp256k1, pass 65 raw bytes
// (r || s || v) or use Sign.
func (a *KeyAuthorization) BuildSigned(signature []byte) ([]interface{}, error) {
	if err := validatePrimitiveSignatureBytes(signature); err != nil {
		return nil, err
	}
	fields, err := a.encodeFields()
	if err != nil {
		return nil, err
	}
	// Copy so later mutation of the caller's slice can't corrupt the result.
	sigCopy := append([]byte(nil), signature...)
	return []interface{}{fields, sigCopy}, nil
}

// validatePrimitiveSignatureBytes checks that signature is a well-formed Tempo
// primitive signature (secp256k1, P256, or WebAuthn).
func validatePrimitiveSignatureBytes(sig []byte) error {
	switch {
	case len(sig) == secp256k1SignatureLength:
		// Canonical Rust to_bytes() uses recovery id 27/28.
		if sig[64] != 27 && sig[64] != 28 {
			return fmt.Errorf("invalid secp256k1 recovery id: got %d, want 27 or 28", sig[64])
		}
		return nil
	case len(sig) == 130 && sig[0] == 0x01:
		return nil // P256: 0x01 || r || s || pub_x || pub_y || pre_hash
	case len(sig) >= 129 && len(sig) <= 2049 && sig[0] == 0x02:
		return nil // WebAuthn: 0x02 || data || r || s || pub_x || pub_y
	default:
		return fmt.Errorf("invalid primitive signature bytes")
	}
}

// SignAndAttach signs the authorization with a secp256k1 key and attaches it to
// the transaction.
//
// Attach the authorization BEFORE signing the transaction: the key
// authorization is part of the transaction's signing payload, so attaching it
// after signing would invalidate the sender (and fee payer) signature. This
// returns an error if the transaction is already signed.
//
// For admin-signed authorizations, set Account (via IntoAdmin or WithAccount).
// For same-tx authorize-and-use, attach first, then sign the carrying
// transaction with the newly authorized key.
func (a *KeyAuthorization) SignAndAttach(tx *transaction.Tx, s *signer.Signer) error {
	if tx == nil {
		return fmt.Errorf("transaction must not be nil")
	}
	if tx.Signature != nil || tx.FeePayerSignature != nil {
		return fmt.Errorf("attach key authorization before signing: it changes the transaction signing payload")
	}

	signed, err := a.Sign(s)
	if err != nil {
		return err
	}
	tx.KeyAuthorization = signed
	return nil
}

// encodeTokenLimits encodes the limits list. A non-nil empty slice encodes as an
// empty RLP list (0xc0), meaning "no spending allowed".
func encodeTokenLimits(limits *[]TokenLimit) []interface{} {
	out := make([]interface{}, 0)
	if limits == nil {
		return out
	}
	for _, l := range *limits {
		// Period is a trailing optional: omit it when zero.
		tuple := []interface{}{l.Token.Bytes(), u256ToBytes(l.Amount)}
		if l.Period != 0 {
			tuple = append(tuple, u64ToBytes(l.Period))
		}
		out = append(out, tuple)
	}
	return out
}

// encodeCallScopes encodes the call-scope list. The nested selector-rule and
// recipient lists are always explicit (empty list means "any").
func encodeCallScopes(scopes *[]CallScope) []interface{} {
	out := make([]interface{}, 0)
	if scopes == nil {
		return out
	}
	for _, s := range *scopes {
		rules := make([]interface{}, 0, len(s.SelectorRules))
		for _, r := range s.SelectorRules {
			recipients := make([]interface{}, 0, len(r.Recipients))
			for _, rec := range r.Recipients {
				recipients = append(recipients, rec.Bytes())
			}
			selector := r.Selector
			rules = append(rules, []interface{}{selector[:], recipients})
		}
		out = append(out, []interface{}{s.Target.Bytes(), rules})
	}
	return out
}

// u64ToBytes returns the minimal big-endian bytes for an RLP integer (0 -> empty).
func u64ToBytes(n uint64) []byte {
	if n == 0 {
		return []byte{}
	}
	return new(big.Int).SetUint64(n).Bytes()
}

// u256ToBytes returns the minimal big-endian bytes for an RLP integer (0/nil -> empty).
func u256ToBytes(n *big.Int) []byte {
	if n == nil || n.Sign() == 0 {
		return []byte{}
	}
	return n.Bytes()
}
