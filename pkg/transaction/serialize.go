package transaction

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/tempoxyz/tempo-go/pkg/signer"
)

// SerializeFormat specifies the serialization format for a transaction.
type SerializeFormat int

const (
	// FormatNormal uses TempoTransaction prefix (0x76) for standard signing (default).
	FormatNormal SerializeFormat = iota
	// FormatFeePayer uses TempoTransaction fee payer prefix (0x78) for fee payer signing.
	FormatFeePayer
)

// String returns a human-readable representation of the serialize format.
// Implements the fmt.Stringer interface.
func (f SerializeFormat) String() string {
	switch f {
	case FormatNormal:
		return "normal"
	case FormatFeePayer:
		return "feePayer"
	default:
		return fmt.Sprintf("unknown(%d)", f)
	}
}

// SerializeOptions contains options for serializing a transaction.
type SerializeOptions struct {
	// Format specifies the serialization format.
	// FormatNormal (default) uses TempoTransaction prefix (0x76) for standard signing.
	// FormatFeePayer uses TempoTransaction fee payer prefix (0x78) for fee payer signing.
	Format SerializeFormat

	// Sender is the sender address, required when Format is FormatFeePayer.
	Sender common.Address

	// ForSigning indicates this is for computing a signing hash (not final broadcast).
	// When true and fee payer is involved, fee_token is skipped per Tempo spec.
	ForSigning bool
}

// Serialize serializes a TempoTransaction to hex string.
// Returns a string starting with TempoTransaction prefix "0x76" or "0x78" (if fee payer format).
func Serialize(tx *Tx, opts *SerializeOptions) (string, error) {
	if opts == nil {
		opts = &SerializeOptions{Format: FormatNormal}
	}

	rlpList, err := buildRLPList(tx, opts)
	if err != nil {
		return "", err
	}

	return encodeWithPrefix(rlpList, opts.Format)
}

// buildRLPList constructs the RLP list for a transaction.
// This contains all 13-14 fields of a TempoTransaction.
func buildRLPList(tx *Tx, opts *SerializeOptions) ([]interface{}, error) {
	rlpList := make([]interface{}, 0, 14)

	// Fields 0-3: Core gas and fee fields
	rlpList = append(rlpList,
		bigIntToBytes(tx.ChainID),
		bigIntToBytes(tx.MaxPriorityFeePerGas),
		bigIntToBytes(tx.MaxFeePerGas),
		uint64ToBytes(tx.Gas),
	)

	// Field 4: calls
	callsRLP, err := encodeCalls(tx.Calls)
	if err != nil {
		return nil, fmt.Errorf("failed to encode calls: %w", err)
	}
	rlpList = append(rlpList, callsRLP)

	// Field 5: accessList
	rlpList = append(rlpList, encodeAccessList(tx.AccessList))

	// Per Tempo spec: skip fee_token in sender's signing payload when fee payer is involved.
	// This allows the fee payer to specify the fee token without invalidating sender's signature.
	// - Only skip when computing sender's signing hash (ForSigning=true, FormatNormal, fee payer involved)
	// - Fee payer format (0x78): always include fee_token (fee payer commits to it)
	// - Final broadcast: always include fee_token
	skipFeeToken := opts.ForSigning && opts.Format == FormatNormal && (tx.AwaitingFeePayer || tx.FeePayerSignature != nil)

	// Fields 6-10: Nonce, validity, and fee token
	rlpList = append(rlpList,
		bigIntToBytes(tx.NonceKey),
		uint64ToBytes(tx.Nonce),
		uint64ToBytes(tx.ValidBefore),
		uint64ToBytes(tx.ValidAfter),
		encodeFeeTokenConditional(tx.FeeToken, skipFeeToken),
	)

	// Field 11: feePayerSignatureOrSender
	rlpList = append(rlpList, encodeFeePayerField(tx, opts))

	// Field 12: authorizationList (empty for now)
	rlpList = append(rlpList, []interface{}{})

	// Field 13: signatureEnvelope (if present)
	if tx.Signature != nil {
		sigEnvelopeBytes, err := encodeSignatureEnvelope(tx.Signature)
		if err != nil {
			return nil, fmt.Errorf("failed to encode signature envelope: %w", err)
		}
		rlpList = append(rlpList, sigEnvelopeBytes)
	}

	return rlpList, nil
}

// encodeFeeToken encodes the fee token address.
// Returns empty bytes if the address is zero (native token).
func encodeFeeToken(token common.Address) []byte {
	if token != (common.Address{}) {
		return token.Bytes()
	}
	return []byte{}
}

// encodeFeeTokenConditional encodes the fee token, optionally skipping it.
// Per Tempo spec, fee_token is skipped (encoded as 0x80/empty) when fee payer is involved
// in the sender's signing payload, allowing the fee payer to specify the fee token.
func encodeFeeTokenConditional(token common.Address, skip bool) []byte {
	if skip {
		return []byte{}
	}
	return encodeFeeToken(token)
}

// encodeFeePayerField encodes field 11 (feePayerSignatureOrSender).
// The encoding depends on the serialization format and whether a fee payer signature exists.
func encodeFeePayerField(tx *Tx, opts *SerializeOptions) interface{} {
	// For fee payer signing format (0x78), include sender address
	if opts.Format == FormatFeePayer {
		return opts.Sender.Bytes()
	}

	// If transaction has fee payer signature, encode it as [yParity, r, s]
	if tx.FeePayerSignature != nil {
		var yParityBytes []byte
		if tx.FeePayerSignature.YParity != 0 {
			yParityBytes = []byte{tx.FeePayerSignature.YParity}
		}
		return []interface{}{
			yParityBytes,
			tx.FeePayerSignature.R.Bytes(),
			tx.FeePayerSignature.S.Bytes(),
		}
	}

	// If awaiting fee payer, use 0x00 marker
	if tx.AwaitingFeePayer {
		return []byte{0x00}
	}

	// No fee payer signature - use empty byte array
	return []byte{}
}

// encodeWithPrefix encodes the RLP list and adds the appropriate TempoTransaction type prefix.
// Returns TempoTransaction prefix "0x76" for normal format, "0x78" for fee payer format.
func encodeWithPrefix(rlpList []interface{}, format SerializeFormat) (string, error) {
	rlpBytes, err := rlp.EncodeToBytes(rlpList)
	if err != nil {
		return "", fmt.Errorf("failed to encode RLP: %w", err)
	}

	prefix := "76"
	if format == FormatFeePayer {
		prefix = "78"
	}

	return "0x" + prefix + hex.EncodeToString(rlpBytes), nil
}

// SerializeForSigning serializes a transaction for sender signing (without signatures).
// Per Tempo Transaction spec (https://docs.tempo.xyz/protocol/transactions/spec-tempo-transaction):
//   - fee_token is SKIPPED (encoded as 0x80) when fee payer is involved
//   - fee_token is INCLUDED when no fee payer (self-paid transaction)
//   - feePayerSignatureOrSender field encoding:
//   - If AwaitingFeePayer=true or FeePayerSignature is set: uses 0x00 marker
//   - Otherwise: uses empty bytes (0x80)
//
// This allows the fee payer to specify the fee token without invalidating the sender's signature.
func SerializeForSigning(tx *Tx) (string, error) {
	txCopy := *tx
	txCopy.Signature = nil
	txCopy.FeePayerSignature = nil

	// Per Tempo spec: if the original tx has fee payer involvement (AwaitingFeePayer=true
	// or FeePayerSignature present), the sender signed with 0x00 marker and fee_token skipped.
	// Preserve this for verification.
	if tx.AwaitingFeePayer || tx.FeePayerSignature != nil {
		txCopy.AwaitingFeePayer = true
	}

	return Serialize(&txCopy, &SerializeOptions{Format: FormatNormal, ForSigning: true})
}

// SerializeForFeePayerSigning serializes a transaction for fee payer signing.
// This uses the 0x78 prefix and includes the sender address.
// IMPORTANT: Must remove BOTH sender and fee payer signatures (per tempo.ts reference).
func SerializeForFeePayerSigning(tx *Tx, sender common.Address) (string, error) {
	if sender == (common.Address{}) {
		return "", fmt.Errorf("sender address is required for fee payer signing")
	}

	// Create a copy without signatures
	txCopy := *tx
	txCopy.Signature = nil         // Remove sender signature (required by tempo.ts)
	txCopy.FeePayerSignature = nil // Remove fee payer signature

	return Serialize(&txCopy, &SerializeOptions{
		Format: FormatFeePayer,
		Sender: sender,
	})
}

// encodeCalls encodes the calls array to RLP.
// Each call is encoded as [to, value, data].
func encodeCalls(calls []Call) ([]interface{}, error) {
	rlpCalls := make([]interface{}, 0, len(calls))

	for _, call := range calls {
		callTuple := make([]interface{}, 3)

		// Field 0: to
		if call.To != nil {
			callTuple[0] = call.To.Bytes()
		} else {
			callTuple[0] = []byte{}
		}

		// Field 1: value
		if call.Value != nil {
			callTuple[1] = call.Value.Bytes()
		} else {
			callTuple[1] = []byte{}
		}

		// Field 2: data
		if call.Data != nil {
			callTuple[2] = call.Data
		} else {
			callTuple[2] = []byte{}
		}

		rlpCalls = append(rlpCalls, callTuple)
	}

	return rlpCalls, nil
}

// encodeAccessList encodes the access list to RLP.
// Each tuple is encoded as [address, [storageKeys]].
func encodeAccessList(accessList AccessList) []interface{} {
	if len(accessList) == 0 {
		return []interface{}{}
	}

	rlpAccessList := make([]interface{}, 0, len(accessList))

	for _, tuple := range accessList {
		// Encode storage keys
		storageKeys := make([]interface{}, 0, len(tuple.StorageKeys))
		for _, key := range tuple.StorageKeys {
			storageKeys = append(storageKeys, key.Bytes())
		}

		// Create tuple [address, [storageKeys]]
		rlpTuple := []interface{}{
			tuple.Address.Bytes(),
			storageKeys,
		}

		rlpAccessList = append(rlpAccessList, rlpTuple)
	}

	return rlpAccessList
}

// encodeSignature encodes a signature to RLP tuple [yParity, r, s].
func encodeSignature(sig *signer.Signature) []interface{} {
	var yParityBytes []byte
	if sig.YParity != 0 {
		yParityBytes = []byte{sig.YParity}
	}
	return []interface{}{
		yParityBytes,
		sig.R.Bytes(),
		sig.S.Bytes(),
	}
}

// encodeSignatureEnvelope encodes a signature envelope.
// Per Tempo Transaction spec, signature types are detected by length and type prefix:
// - secp256k1: raw 65 bytes (r || s || yParity) - no type prefix
// - keychain: raw bytes (0x04 || user_address || inner_sig) - type prefix 0x04
// - p256: raw bytes (0x01 || signature data) - type prefix 0x01
// - webauthn: raw bytes (0x02 || webauthn_data) - type prefix 0x02
func encodeSignatureEnvelope(envelope *signer.SignatureEnvelope) ([]byte, error) {
	if envelope == nil {
		return []byte{}, nil
	}

	// secp256k1: raw 65 bytes (no type prefix)
	if envelope.Type == "secp256k1" || envelope.Type == "" {
		if envelope.Signature == nil {
			return nil, fmt.Errorf("secp256k1 signature envelope has no parsed signature")
		}

		rBytes := envelope.Signature.R.Bytes()
		if len(rBytes) > 32 {
			return nil, fmt.Errorf("signature R exceeds 32 bytes: got %d", len(rBytes))
		}

		sBytes := envelope.Signature.S.Bytes()
		if len(sBytes) > 32 {
			return nil, fmt.Errorf("signature S exceeds 32 bytes: got %d", len(sBytes))
		}

		if envelope.Signature.YParity > 1 {
			return nil, fmt.Errorf("invalid yParity: must be 0 or 1, got %d", envelope.Signature.YParity)
		}

		result := make([]byte, 65)
		copy(result[32-len(rBytes):32], rBytes)
		copy(result[64-len(sBytes):64], sBytes)
		result[64] = envelope.Signature.YParity

		return result, nil
	}

	// keychain, p256, webauthn: use raw bytes directly (already includes type prefix)
	if envelope.Raw != nil {
		return envelope.Raw, nil
	}

	return nil, fmt.Errorf("signature envelope type %q has no raw bytes", envelope.Type)
}

// bigIntToBytes converts a *big.Int to bytes, returning empty bytes for nil or 0.
func bigIntToBytes(n *big.Int) []byte {
	if n == nil || n.Sign() == 0 {
		return []byte{}
	}
	return n.Bytes()
}

// uint64ToBytes converts a uint64 to bytes, returning empty bytes for 0.
func uint64ToBytes(n uint64) []byte {
	if n == 0 {
		return []byte{}
	}
	return new(big.Int).SetUint64(n).Bytes()
}
