package transaction

import (
	"encoding/hex"
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
// RLP Structure (from tempo.ts):
// [
//
//	chainId,
//	maxPriorityFeePerGas,
//	maxFeePerGas,
//	gas,
//	calls,                    // Array of [to, value, data] tuples
//	accessList,               // Array of [address, [storageKeys]] tuples
//	nonceKey,
//	nonce,
//	validBefore,
//	validAfter,
//	feeToken,
//	feePayerSignatureOrSender,  // Signature [yParity, r, s] or "0x00" or empty
//	authorizationList,          // Empty array for now
//	signatureEnvelope           // Sender's signature
//
// ]
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

	// Validate we have the correct number of fields (13 or 14)
	if len(raw) != 13 && len(raw) != 14 {
		return nil, fmt.Errorf("invalid RLP structure: expected 13 or 14 fields, got %d", len(raw))
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
		tx.Gas = new(big.Int).SetBytes(gas).Uint64()
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
		tx.Nonce = new(big.Int).SetBytes(nonce).Uint64()
	}

	// Field 8: validBefore
	if validBefore, ok := raw[8].([]byte); ok && len(validBefore) > 0 {
		tx.ValidBefore = new(big.Int).SetBytes(validBefore).Uint64()
	}

	// Field 9: validAfter
	if validAfter, ok := raw[9].([]byte); ok && len(validAfter) > 0 {
		tx.ValidAfter = new(big.Int).SetBytes(validAfter).Uint64()
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

	// Field 12: authorizationList (currently empty)
	// Future: EIP-7702 authorization list support will be added when the spec is finalized.
	// This field is currently always an empty array in Tempo transactions.

	// Field 13: signatureEnvelope (if present)
	if len(raw) > 13 {
		if sigEnvelopeRaw, ok := raw[13].([]byte); ok && len(sigEnvelopeRaw) > 0 {
			sigEnvelope, err := decodeSignatureEnvelope(sigEnvelopeRaw)
			if err != nil {
				return nil, fmt.Errorf("failed to decode signature envelope: %w", err)
			}
			tx.Signature = sigEnvelope
		}
	}

	return tx, nil
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
	var yParity uint8
	if len(yParityBytes) > 0 {
		yParity = yParityBytes[0]
		// Convert legacy V value (27/28) to yParity (0/1) if needed
		if yParity >= 27 {
			yParity -= 27
		}
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
// The envelope is RLP-encoded as [signatureType, signature].
func decodeSignatureEnvelope(envelopeBytes []byte) (*signer.SignatureEnvelope, error) {
	// tempo.ts v0.4.2+ backward compatibility:
	// For secp256k1, the signature envelope is a raw 65-byte signature (not a list)
	// Format: r (32 bytes) + s (32 bytes) + yParity (1 byte)
	if len(envelopeBytes) == 65 {
		r := new(big.Int).SetBytes(envelopeBytes[0:32])
		s := new(big.Int).SetBytes(envelopeBytes[32:64])
		yParity := uint8(envelopeBytes[64])

		// Convert legacy V value (27/28) to yParity (0/1) if needed
		if yParity >= 27 {
			yParity -= 27
		}

		return &signer.SignatureEnvelope{
			Type:      "secp256k1",
			Signature: signer.NewSignature(r, s, yParity),
		}, nil
	}

	// For other signature types (p256, webauthn), try structured decoding
	var raw []interface{}
	if err := rlp.DecodeBytes(envelopeBytes, &raw); err != nil {
		return nil, fmt.Errorf("failed to decode signature envelope RLP: %w", err)
	}

	if len(raw) != 2 {
		return nil, fmt.Errorf("invalid signature envelope length: expected 2, got %d", len(raw))
	}

	// Field 0: signature type
	typeBytes, ok := raw[0].([]byte)
	if !ok {
		return nil, fmt.Errorf("signature type is not bytes")
	}
	sigType := string(typeBytes)

	// Field 1: signature tuple [yParity, r, s]
	sigTuple, ok := raw[1].([]interface{})
	if !ok {
		return nil, fmt.Errorf("signature is not a tuple")
	}

	sig, err := decodeSignature(sigTuple)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	return &signer.SignatureEnvelope{
		Type:      sigType,
		Signature: sig,
	}, nil
}
