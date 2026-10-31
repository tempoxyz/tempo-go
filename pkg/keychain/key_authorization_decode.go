package keychain

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

// Field positions in the RLP list of an unsigned key authorization:
// [chain_id, key_type, key_id, expiry?, limits?, allowed_calls?, witness?, is_admin?, account?].
const (
	keyAuthRequiredFields = 3
	keyAuthMaxFields      = 9
)

// DecodeKeyAuthorization decodes a signed key authorization as it appears in a
// transaction (transaction.Tx.KeyAuthorization after transaction.Deserialize)
// or as Sign and BuildSigned return it: [authorization, signature]. It is the
// inverse of BuildSigned.
//
// The returned signature is the root or admin key's primitive signature: for
// secp256k1, 65 bytes r || s || v with v normalized to 27/28 (0/1 is accepted,
// as the node accepts it); for P256 and WebAuthn, the raw bytes with their type
// prefix.
//
// Decoding follows tempo-primitives: integers must be minimally encoded,
// addresses must be 20 bytes, and an absent optional field may be written as an
// empty placeholder (0x80) only when a later field is present. Semantic rules
// such as "admin keys cannot have limits" are not enforced here; call Validate
// on the result for those.
func DecodeKeyAuthorization(signed []interface{}) (*KeyAuthorization, []byte, error) {
	if len(signed) != 2 {
		return nil, nil, fmt.Errorf("signed key authorization: expected 2 items [authorization, signature], got %d", len(signed))
	}
	fields, ok := signed[0].([]interface{})
	if !ok {
		return nil, nil, fmt.Errorf("signed key authorization: authorization is not a list")
	}
	auth, err := decodeKeyAuthorizationFields(fields)
	if err != nil {
		return nil, nil, err
	}
	sigBytes, ok := signed[1].([]byte)
	if !ok {
		return nil, nil, fmt.Errorf("signed key authorization: signature is not a byte string")
	}
	sig, err := decodePrimitiveSignatureBytes(sigBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("signed key authorization: %w", err)
	}
	return auth, sig, nil
}

func decodeKeyAuthorizationFields(fields []interface{}) (*KeyAuthorization, error) {
	if len(fields) < keyAuthRequiredFields || len(fields) > keyAuthMaxFields {
		return nil, fmt.Errorf("key authorization: expected %d to %d fields, got %d", keyAuthRequiredFields, keyAuthMaxFields, len(fields))
	}

	chainID, err := decodeRLPUint64(fields[0], "key authorization chainId")
	if err != nil {
		return nil, err
	}
	keyType, err := decodeRLPUint64(fields[1], "key authorization keyType")
	if err != nil {
		return nil, err
	}
	if keyType > SignatureTypeWebAuthn {
		return nil, fmt.Errorf("key authorization: unsupported keyType %d", keyType)
	}
	keyID, err := decodeRLPAddress(fields[2], "key authorization keyId")
	if err != nil {
		return nil, err
	}
	auth := NewKeyAuthorization(chainID, uint8(keyType), keyID)

	last := len(fields) - 1
	for i := keyAuthRequiredFields; i <= last; i++ {
		f := fields[i]
		// An empty string placeholder marks an absent field, but only before a
		// present one: trailing absent fields must be omitted. The node rejects an
		// explicit trailing 0x80 when decoding the transaction.
		if b, isBytes := f.([]byte); isBytes && len(b) == 0 && i < last {
			continue
		}
		switch i {
		case 3:
			expiry, err := decodeRLPUint64(f, "key authorization expiry")
			if err != nil {
				return nil, err
			}
			if expiry == 0 {
				return nil, fmt.Errorf("key authorization: expiry must be omitted, not encoded as 0")
			}
			auth.Expiry = expiry
		case 4:
			limits, err := decodeTokenLimits(f)
			if err != nil {
				return nil, err
			}
			auth.Limits = &limits
		case 5:
			scopes, err := decodeCallScopes(f)
			if err != nil {
				return nil, err
			}
			auth.AllowedCalls = &scopes
		case 6:
			b, isBytes := f.([]byte)
			if !isBytes || len(b) != common.HashLength {
				return nil, fmt.Errorf("key authorization: witness must be %d bytes", common.HashLength)
			}
			witness := common.BytesToHash(b)
			auth.Witness = &witness
		case 7:
			b, isBytes := f.([]byte)
			if !isBytes || len(b) != 1 || b[0] != 0x01 {
				return nil, fmt.Errorf("key authorization: invalid admin key authorization marker")
			}
			auth.IsAdmin = true
		case 8:
			account, err := decodeRLPAddress(f, "key authorization account")
			if err != nil {
				return nil, err
			}
			auth.Account = &account
		}
	}
	return auth, nil
}

// decodeTokenLimits decodes the limits list: [[token, limit, period?], ...].
func decodeTokenLimits(f interface{}) ([]TokenLimit, error) {
	list, ok := f.([]interface{})
	if !ok {
		return nil, fmt.Errorf("key authorization: limits is not a list")
	}
	limits := make([]TokenLimit, 0, len(list))
	for i, item := range list {
		tuple, ok := item.([]interface{})
		if !ok || len(tuple) < 2 || len(tuple) > 3 {
			return nil, fmt.Errorf("key authorization: limits[%d] must be a list of 2 or 3 items", i)
		}
		token, err := decodeRLPAddress(tuple[0], fmt.Sprintf("limits[%d].token", i))
		if err != nil {
			return nil, err
		}
		amount, err := decodeRLPUint256(tuple[1], fmt.Sprintf("limits[%d].limit", i))
		if err != nil {
			return nil, err
		}
		limit := TokenLimit{Token: token, Amount: amount}
		if len(tuple) == 3 {
			// period is a trailing optional: present only when non-zero.
			period, err := decodeRLPUint64(tuple[2], fmt.Sprintf("limits[%d].period", i))
			if err != nil {
				return nil, err
			}
			// The node rejects an explicit zero period: a one-time limit omits it.
			if period == 0 {
				return nil, fmt.Errorf("key authorization: limits[%d].period must be omitted, not encoded as 0", i)
			}
			limit.Period = period
		}
		limits = append(limits, limit)
	}
	return limits, nil
}

// decodeCallScopes decodes the allowed calls list:
// [[target, [[selector, [recipient, ...]], ...]], ...].
func decodeCallScopes(f interface{}) ([]CallScope, error) {
	list, ok := f.([]interface{})
	if !ok {
		return nil, fmt.Errorf("key authorization: allowed calls is not a list")
	}
	scopes := make([]CallScope, 0, len(list))
	for i, item := range list {
		tuple, ok := item.([]interface{})
		if !ok || len(tuple) != 2 {
			return nil, fmt.Errorf("key authorization: allowedCalls[%d] must be a list of 2 items", i)
		}
		target, err := decodeRLPAddress(tuple[0], fmt.Sprintf("allowedCalls[%d].target", i))
		if err != nil {
			return nil, err
		}
		rulesRaw, ok := tuple[1].([]interface{})
		if !ok {
			return nil, fmt.Errorf("key authorization: allowedCalls[%d].selectorRules is not a list", i)
		}
		rules := make([]SelectorRule, 0, len(rulesRaw))
		for j, ruleRaw := range rulesRaw {
			rule, ok := ruleRaw.([]interface{})
			if !ok || len(rule) != 2 {
				return nil, fmt.Errorf("key authorization: allowedCalls[%d].selectorRules[%d] must be a list of 2 items", i, j)
			}
			selector, ok := rule[0].([]byte)
			if !ok || len(selector) != 4 {
				return nil, fmt.Errorf("key authorization: allowedCalls[%d].selectorRules[%d].selector must be 4 bytes", i, j)
			}
			recipientsRaw, ok := rule[1].([]interface{})
			if !ok {
				return nil, fmt.Errorf("key authorization: allowedCalls[%d].selectorRules[%d].recipients is not a list", i, j)
			}
			recipients := make([]common.Address, 0, len(recipientsRaw))
			for k, recRaw := range recipientsRaw {
				rec, err := decodeRLPAddress(recRaw, fmt.Sprintf("allowedCalls[%d].selectorRules[%d].recipients[%d]", i, j, k))
				if err != nil {
					return nil, err
				}
				recipients = append(recipients, rec)
			}
			var sel [4]byte
			copy(sel[:], selector)
			rules = append(rules, SelectorRule{Selector: sel, Recipients: recipients})
		}
		scopes = append(scopes, CallScope{Target: target, SelectorRules: rules})
	}
	return scopes, nil
}

// decodePrimitiveSignatureBytes checks a primitive signature (secp256k1, P256
// or WebAuthn) and returns a copy, with a secp256k1 recovery id given as 0/1
// normalized to 27/28.
func decodePrimitiveSignatureBytes(sig []byte) ([]byte, error) {
	out := append([]byte(nil), sig...)
	if len(out) == secp256k1SignatureLength {
		v, err := normalizeRecoveryID(out[64])
		if err != nil {
			return nil, err
		}
		out[64] = v
		return out, nil
	}
	if err := validatePrimitiveSignatureBytes(out); err != nil {
		return nil, err
	}
	return out, nil
}

// decodeRLPUint64 decodes a minimally encoded RLP integer that fits in a uint64.
func decodeRLPUint64(f interface{}, name string) (uint64, error) {
	b, ok := f.([]byte)
	if !ok {
		return 0, fmt.Errorf("%s: expected an integer, got a list", name)
	}
	if len(b) > 8 {
		return 0, fmt.Errorf("%s: exceeds uint64", name)
	}
	if len(b) > 0 && b[0] == 0 {
		return 0, fmt.Errorf("%s: non-canonical integer (leading zero)", name)
	}
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v, nil
}

// decodeRLPUint256 decodes a minimally encoded RLP integer that fits in 256 bits.
func decodeRLPUint256(f interface{}, name string) (*big.Int, error) {
	b, ok := f.([]byte)
	if !ok {
		return nil, fmt.Errorf("%s: expected an integer, got a list", name)
	}
	if len(b) > 32 {
		return nil, fmt.Errorf("%s: exceeds uint256", name)
	}
	if len(b) > 0 && b[0] == 0 {
		return nil, fmt.Errorf("%s: non-canonical integer (leading zero)", name)
	}
	return new(big.Int).SetBytes(b), nil
}

// decodeRLPAddress decodes a 20-byte address.
func decodeRLPAddress(f interface{}, name string) (common.Address, error) {
	b, ok := f.([]byte)
	if !ok || len(b) != common.AddressLength {
		return common.Address{}, fmt.Errorf("%s: expected a %d-byte address", name, common.AddressLength)
	}
	return common.BytesToAddress(b), nil
}
