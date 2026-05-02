package transaction

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/tempoxyz/tempo-go/pkg/signer"
)

// Deserialize parses a serialized TempoTransaction.
// The serialized transaction must start with TempoTransaction prefix "0x76".
//
// RLP Structure:
// [
//
//	chainId,                      // 0
//	maxPriorityFeePerGas,         // 1
//	maxFeePerGas,                 // 2
//	gas,                          // 3
//	calls,                        // 4  Array of [to, value, data] tuples
//	accessList,                   // 5  Array of [address, [storageKeys]] tuples
//	nonceKey,                     // 6
//	nonce,                        // 7
//	validBefore,                  // 8
//	validAfter,                   // 9
//	feeToken,                     // 10
//	feePayerSignatureOrSender,    // 11 Signature [yParity, r, s] or "0x00" or empty
//	authorizationList,            // 12 Empty array (reserved for EIP-7702)
//	keyAuthorizationOrSignature,  // 13 (optional) keyAuthorization (list) or signatureEnvelope (bytes)
//	maybeSignature,               // 14 (optional) signatureEnvelope when field 13 is keyAuthorization
//
// ]
//
// Field counts:
//   - 13 fields: unsigned (no keyAuthorization, no signature)
//   - 14 fields: signed (no keyAuthorization) OR unsigned with keyAuthorization
//   - 15 fields: signed with keyAuthorization (access keys)
func Deserialize(serialized string) (*Tx, error) {
	// Remove 0x prefix if present
	serialized = strings.TrimPrefix(serialized, "0x")

	// Check for empty data
	if len(serialized) < 2 {
		return nil, fmt.Errorf("%w: too short", ErrInvalidTransaction)
	}

	// Check for TempoTransaction prefix
	if !strings.HasPrefix(serialized, "76") {
		return nil, fmt.Errorf("%w: expected TempoTransaction prefix 0x76, got 0x%s", ErrInvalidTransactionType, serialized[:2])
	}

	// Remove 76 prefix
	serialized = serialized[2:]

	// tempo.ts v0.4.2+ appends sender address + marker when feePayer=true
	// Format: <rlp_data> + <20_byte_address> + "feefeefeefee"
	// We need to strip this before RLP decoding
	if strings.HasSuffix(serialized, "feefeefeefee") && len(serialized) >= 52 {
		// 52 = 40 chars (20 bytes address) + 12 chars (6 bytes marker)
		serialized = serialized[:len(serialized)-52]
	}

	// Decode hex to bytes
	rlpBytes, err := hex.DecodeString(serialized)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex: %w", err)
	}

	// Decode RLP to raw interface slice
	var raw []interface{}
	if err := rlp.DecodeBytes(rlpBytes, &raw); err != nil {
		return nil, fmt.Errorf("failed to decode RLP: %w", err)
	}

	// Validate we have the correct number of fields (13, 14, or 15)
	if len(raw) != 13 && len(raw) != 14 && len(raw) != 15 {
		return nil, fmt.Errorf("invalid RLP structure: expected 13, 14, or 15 fields, got %d", len(raw))
	}

	tx := New()

	// Parse fields in order
	// Field 0: chainId
	if chainID, ok := raw[0].([]byte); ok && len(chainID) > 0 {
		tx.ChainID = new(big.Int).SetBytes(chainID)
	}

	// Field 1: maxPriorityFeePerGas
	if maxPriorityFeePerGas, ok := raw[1].([]byte); ok && len(maxPriorityFeePerGas) > 0 {
		tx.MaxPriorityFeePerGas = new(big.Int).SetBytes(maxPriorityFeePerGas)
	}

	// Field 2: maxFeePerGas
	if maxFeePerGas, ok := raw[2].([]byte); ok && len(maxFeePerGas) > 0 {
		tx.MaxFeePerGas = new(big.Int).SetBytes(maxFeePerGas)
	}

	// Field 3: gas
	if gas, ok := raw[3].([]byte); ok && len(gas) > 0 {
		v, err := bytesToUint64(gas)
		if err != nil {
			return nil, fmt.Errorf("gas %v", err)
		}
		tx.Gas = v
	}

	// Field 4: calls - array of [to, value, data] tuples
	if callsRaw, ok := raw[4].([]interface{}); ok {
		calls, err := decodeCalls(callsRaw)
		if err != nil {
			return nil, fmt.Errorf("failed to decode calls: %w", err)
		}
		tx.Calls = calls
	}

	// Field 5: accessList - array of [address, [storageKeys]] tuples
	if accessListRaw, ok := raw[5].([]interface{}); ok {
		accessList, err := decodeAccessList(accessListRaw)
		if err != nil {
			return nil, fmt.Errorf("failed to decode access list: %w", err)
		}
		tx.AccessList = accessList
	}

	// Field 6: nonceKey
	if nonceKey, ok := raw[6].([]byte); ok && len(nonceKey) > 0 {
		tx.NonceKey = new(big.Int).SetBytes(nonceKey)
	}

	// Field 7: nonce
	if nonce, ok := raw[7].([]byte); ok && len(nonce) > 0 {
		v, err := bytesToUint64(nonce)
		if err != nil {
			return nil, fmt.Errorf("nonce %v", err)
		}
		tx.Nonce = v
	}

	// Field 8: validBefore
	if validBefore, ok := raw[8].([]byte); ok && len(validBefore) > 0 {
		v, err := bytesToUint64(validBefore)
		if err != nil {
			return nil, fmt.Errorf("validBefore %v", err)
		}
		tx.ValidBefore = v
	}

	// Field 9: validAfter
	if validAfter, ok := raw[9].([]byte); ok && len(validAfter) > 0 {
		v, err := bytesToUint64(validAfter)
		if err != nil {
			return nil, fmt.Errorf("validAfter %v", err)
		}
		tx.ValidAfter = v
	}

	// Field 10: feeToken
	if feeToken, ok := raw[10].([]byte); ok && len(feeToken) > 0 {
		tx.FeeToken = common.BytesToAddress(feeToken)
	}

	// Field 11: feePayerSignatureOrSender
	// This can be:
	// - Empty (0x) - no fee payer signature yet
	// - "0x00" - indicates awaiting fee payer (null marker)
	// - Signature tuple [yParity, r, s]
	if feePayerSigRaw, ok := raw[11].([]byte); ok {
		if len(feePayerSigRaw) == 1 && feePayerSigRaw[0] == 0x00 {
			// "0x00" marker - awaiting fee payer
			tx.FeePayerSignature = nil
			tx.AwaitingFeePayer = true
		} else if len(feePayerSigRaw) > 0 {
			// Non-empty bytes that aren't 0x00 - unusual case
		}
	} else if feePayerSigTuple, ok := raw[11].([]interface{}); ok && len(feePayerSigTuple) == 3 {
		// Signature tuple: [yParity, r, s]
		sig, err := decodeSignature(feePayerSigTuple)
		if err != nil {
			return nil, fmt.Errorf("failed to decode fee payer signature: %w", err)
		}
		tx.FeePayerSignature = sig
	}

	// Field 12: authorizationList (reserved for EIP-7702)

	// Fields 13-14: keyAuthorization and/or signatureEnvelope.
	// Field shape must be validated strictly to reject malformed trailing fields.
	switch len(raw) {
	case 13:
		// No optional fields.
	case 14:
		if keyAuth, isList := raw[13].([]interface{}); isList {
			tx.KeyAuthorization = keyAuth
			break
		}

		sigEnvelope, err := parseSignatureEnvelopeField(raw[13], 13, true)
		if err != nil {
			return nil, err
		}
		tx.Signature = sigEnvelope
	case 15:
		keyAuth, isList := raw[13].([]interface{})
		if !isList {
			return nil, fmt.Errorf("invalid field 13 type for 15-field transaction: expected keyAuthorization list")
		}
		tx.KeyAuthorization = keyAuth

		sigEnvelope, err := parseSignatureEnvelopeField(raw[14], 14, true)
		if err != nil {
			return nil, err
		}
		tx.Signature = sigEnvelope
	}

	return tx, nil
}

// parseSignatureEnvelopeField parses a signature envelope from a raw RLP field.
func parseSignatureEnvelopeField(field interface{}, index int, requireNonEmpty bool) (*signer.SignatureEnvelope, error) {
	sigEnvelopeRaw, ok := field.([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid field %d type: expected signatureEnvelope bytes", index)
	}
	if len(sigEnvelopeRaw) == 0 {
		if requireNonEmpty {
			return nil, fmt.Errorf("invalid field %d: expected non-empty signatureEnvelope bytes", index)
		}
		return nil, nil
	}

	sigEnvelope, err := decodeSignatureEnvelope(sigEnvelopeRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature envelope: %w", err)
	}

	return sigEnvelope, nil
}

// decodeCalls decodes the calls array from RLP.
// Each call is encoded as [to, value, data].
func decodeCalls(callsRaw []interface{}) ([]Call, error) {
	calls := make([]Call, 0, len(callsRaw))

	for i, callRaw := range callsRaw {
		callTuple, ok := callRaw.([]interface{})
		if !ok {
			return nil, fmt.Errorf("call %d is not a tuple", i)
		}

		if len(callTuple) != 3 {
			return nil, fmt.Errorf("call %d has invalid length: expected 3, got %d", i, len(callTuple))
		}

		call := Call{
			Value: big.NewInt(0),
			Data:  []byte{},
		}

		// Field 0: to (address or empty for contract creation)
		if to, ok := callTuple[0].([]byte); ok && len(to) > 0 {
			addr := common.BytesToAddress(to)
			call.To = &addr
		}

		// Field 1: value
		if value, ok := callTuple[1].([]byte); ok && len(value) > 0 {
			call.Value = new(big.Int).SetBytes(value)
		}

		// Field 2: data
		if data, ok := callTuple[2].([]byte); ok {
			call.Data = data
		}

		calls = append(calls, call)
	}

	return calls, nil
}

// decodeAccessList decodes the access list from RLP.
// Each tuple is encoded as [address, [storageKeys]].
func decodeAccessList(accessListRaw []interface{}) (AccessList, error) {
	accessList := make(AccessList, 0, len(accessListRaw))

	for i, tupleRaw := range accessListRaw {
		tuple, ok := tupleRaw.([]interface{})
		if !ok {
			return nil, fmt.Errorf("access list entry %d is not a tuple", i)
		}

		if len(tuple) != 2 {
			return nil, fmt.Errorf("access list entry %d has invalid length: expected 2, got %d", i, len(tuple))
		}

		// Field 0: address
		addressBytes, ok := tuple[0].([]byte)
		if !ok {
			return nil, fmt.Errorf("access list entry %d address is not bytes", i)
		}
		address := common.BytesToAddress(addressBytes)

		// Field 1: storage keys
		storageKeysRaw, ok := tuple[1].([]interface{})
		if !ok {
			return nil, fmt.Errorf("access list entry %d storage keys is not an array", i)
		}

		storageKeys := make([]common.Hash, 0, len(storageKeysRaw))
		for j, keyRaw := range storageKeysRaw {
			keyBytes, ok := keyRaw.([]byte)
			if !ok {
				return nil, fmt.Errorf("access list entry %d storage key %d is not bytes", i, j)
			}
			storageKeys = append(storageKeys, common.BytesToHash(keyBytes))
		}

		accessList = append(accessList, AccessTuple{
			Address:     address,
			StorageKeys: storageKeys,
		})
	}

	return accessList, nil
}

// maxSignatureScalarBytes is the maximum byte length for secp256k1 signature scalars (R and S).
// Valid signature components must fit within 32 bytes (256 bits).
const maxSignatureScalarBytes = 32

func decodeYParity(yParityBytes []byte, context string) (uint8, error) {
	if len(yParityBytes) == 0 {
		return 0, nil
	}
	if len(yParityBytes) != 1 {
		return 0, fmt.Errorf("invalid %s: expected single byte, got %d bytes", context, len(yParityBytes))
	}

	yParity := yParityBytes[0]
	if yParity > 1 {
		return 0, fmt.Errorf("invalid %s: must be 0 or 1, got %d", context, yParity)
	}

	return yParity, nil
}

// decodeSignature decodes a signature tuple [yParity, r, s].
func decodeSignature(sigTuple []interface{}) (*signer.Signature, error) {
	if len(sigTuple) != 3 {
		return nil, fmt.Errorf("invalid signature tuple length: expected 3, got %d", len(sigTuple))
	}

	// Field 0: yParity (0 or 1)
	yParityBytes, ok := sigTuple[0].([]byte)
	if !ok {
		return nil, fmt.Errorf("yParity is not bytes")
	}
	yParity, err := decodeYParity(yParityBytes, "yParity")
	if err != nil {
		return nil, err
	}

	// Field 1: r
	rBytes, ok := sigTuple[1].([]byte)
	if !ok {
		return nil, fmt.Errorf("r is not bytes")
	}
	// Validate R size to prevent DoS via oversized signature components.
	// Oversized values would cause a panic in RecoverAddress when using FillBytes.
	if len(rBytes) > maxSignatureScalarBytes {
		return nil, fmt.Errorf("r exceeds maximum size: got %d bytes, max %d", len(rBytes), maxSignatureScalarBytes)
	}
	r := new(big.Int).SetBytes(rBytes)

	// Field 2: s
	sBytes, ok := sigTuple[2].([]byte)
	if !ok {
		return nil, fmt.Errorf("s is not bytes")
	}
	// Validate S size to prevent DoS via oversized signature components.
	if len(sBytes) > maxSignatureScalarBytes {
		return nil, fmt.Errorf("s exceeds maximum size: got %d bytes, max %d", len(sBytes), maxSignatureScalarBytes)
	}
	s := new(big.Int).SetBytes(sBytes)

	return signer.NewSignature(r, s, yParity), nil
}

// decodeSignatureEnvelope decodes a signature envelope.
// Per Tempo Transaction spec, signature types are detected by length and type prefix:
// - secp256k1: raw 65 bytes (r || s || yParity) - no type prefix
// - keychain: 0x04 + user_address (20 bytes) + inner_sig (65 bytes) = 86 bytes
// - p256: 0x01 + 129 bytes = 130 bytes
// - webauthn: 0x02 + variable data (129-2049 bytes total)
func decodeSignatureEnvelope(envelopeBytes []byte) (*signer.SignatureEnvelope, error) {
	if len(envelopeBytes) == 0 {
		return nil, nil
	}

	// secp256k1: exactly 65 bytes with no type prefix
	if len(envelopeBytes) == 65 {
		r := new(big.Int).SetBytes(envelopeBytes[0:32])
		s := new(big.Int).SetBytes(envelopeBytes[32:64])
		yParity, err := decodeYParity([]byte{envelopeBytes[64]}, "yParity in signature envelope")
		if err != nil {
			return nil, err
		}

		return &signer.SignatureEnvelope{
			Type:      "secp256k1",
			Signature: signer.NewSignature(r, s, yParity),
		}, nil
	}

	// Check type prefix for other signature types
	if len(envelopeBytes) < 1 {
		return nil, fmt.Errorf("signature envelope too short")
	}

	typePrefix := envelopeBytes[0]

	switch typePrefix {
	case 0x01: // P256: 0x01 + 129 bytes = 130 bytes
		if len(envelopeBytes) != 130 {
			return nil, fmt.Errorf("invalid P256 signature length: expected 130, got %d", len(envelopeBytes))
		}
		return &signer.SignatureEnvelope{
			Type: "p256",
			Raw:  envelopeBytes,
		}, nil

	case 0x02: // WebAuthn: 0x02 + variable (129-2049 bytes total)
		if len(envelopeBytes) < 129 || len(envelopeBytes) > 2049 {
			return nil, fmt.Errorf("invalid WebAuthn signature length: got %d, expected 129-2049", len(envelopeBytes))
		}
		return &signer.SignatureEnvelope{
			Type: "webauthn",
			Raw:  envelopeBytes,
		}, nil

	case 0x04: // Keychain: 0x04 + user_address (20 bytes) + inner_sig (65 bytes) = 86 bytes
		if len(envelopeBytes) != 86 {
			return nil, fmt.Errorf("invalid Keychain signature length: expected 86, got %d", len(envelopeBytes))
		}
		return &signer.SignatureEnvelope{
			Type: "keychain",
			Raw:  envelopeBytes,
		}, nil

	default:
		return nil, fmt.Errorf("unknown signature type prefix: 0x%02x", typePrefix)
	}
}

// bytesToUint64 converts a byte slice to uint64, returning an error if it exceeds uint64 range.
func bytesToUint64(b []byte) (uint64, error) {
	v := new(big.Int).SetBytes(b)
	if !v.IsUint64() {
		return 0, errors.New("exceeds uint64 maximum")
	}
	return v.Uint64(), nil
}
