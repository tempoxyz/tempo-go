package transaction

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildKeyAuthRLPList constructs a raw RLP field list for testing deserialization.
// The caller controls which optional fields (keyAuthorization, signatureEnvelope) are appended.
func buildKeyAuthRLPList(keyAuth []interface{}, sigEnvelope []byte) []interface{} {
	list := []interface{}{
		big.NewInt(42424).Bytes(),   // 0: chainId
		big.NewInt(1000000).Bytes(), // 1: maxPriorityFeePerGas
		big.NewInt(2000000).Bytes(), // 2: maxFeePerGas
		big.NewInt(21000).Bytes(),   // 3: gas
		[]interface{}{ // 4: calls
			[]interface{}{
				common.HexToAddress("0x1234567890123456789012345678901234567890").Bytes(),
				big.NewInt(1000000).Bytes(),
				[]byte{0xde, 0xad},
			},
		},
		[]interface{}{},       // 5: accessList
		[]byte{},              // 6: nonceKey (0)
		big.NewInt(1).Bytes(), // 7: nonce
		[]byte{},              // 8: validBefore
		[]byte{},              // 9: validAfter
		common.HexToAddress("0x20c0000000000000000000000000000000000001").Bytes(), // 10: feeToken
		[]byte{0x00},    // 11: feePayerSignature (awaiting)
		[]interface{}{}, // 12: authorizationList
	}
	if keyAuth != nil {
		list = append(list, keyAuth)
	}
	if sigEnvelope != nil {
		list = append(list, sigEnvelope)
	}
	return list
}

func encodeToHex(t *testing.T, rlpList []interface{}) string {
	t.Helper()
	rlpBytes, err := rlp.EncodeToBytes(rlpList)
	require.NoError(t, err)
	return "0x76" + hex.EncodeToString(rlpBytes)
}

func makeSecp256k1Envelope() ([]byte, *big.Int, *big.Int) {
	r := hexToBigInt("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
	s := hexToBigInt("0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321")
	envelope := make([]byte, 65)
	copy(envelope[0:32], r.Bytes())
	copy(envelope[32:64], s.Bytes())
	envelope[64] = 0x00 // yParity
	return envelope, r, s
}

// TestDeserialize_KeyAuthorization_15Fields tests that a 15-field RLP list
// (13 base + keyAuthorization list + signatureEnvelope bytes) is deserialized correctly.
func TestDeserialize_KeyAuthorization_15Fields(t *testing.T) {
	sigEnvelope, sigR, sigS := makeSecp256k1Envelope()
	keyAuthTuple := []interface{}{
		common.HexToAddress("0xabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd").Bytes(),
		[]byte{0x01, 0x02, 0x03},
		big.NewInt(9999999).Bytes(),
	}

	serialized := encodeToHex(t, buildKeyAuthRLPList(keyAuthTuple, sigEnvelope))

	tx, err := Deserialize(serialized)
	require.NoError(t, err)

	assert.Equal(t, 0, tx.ChainID.Cmp(big.NewInt(42424)), "ChainID mismatch")
	assert.Equal(t, uint64(21000), tx.Gas, "Gas mismatch")
	assert.Equal(t, uint64(1), tx.Nonce, "Nonce mismatch")
	assert.True(t, tx.AwaitingFeePayer, "AwaitingFeePayer should be true (0x00 marker)")

	// keyAuthorization at field 13
	require.NotNil(t, tx.KeyAuthorization, "KeyAuthorization should be parsed from field 13")
	keyAuth, ok := tx.KeyAuthorization.([]interface{})
	require.True(t, ok, "KeyAuthorization should be a list")
	assert.Len(t, keyAuth, 3, "KeyAuthorization tuple should have 3 elements")

	// signatureEnvelope at field 14
	require.NotNil(t, tx.Signature, "Signature should be parsed from field 14")
	assert.Equal(t, "secp256k1", tx.Signature.Type)
	assert.Equal(t, 0, tx.Signature.Signature.R.Cmp(sigR), "Signature R mismatch")
	assert.Equal(t, 0, tx.Signature.Signature.S.Cmp(sigS), "Signature S mismatch")
}

// TestDeserialize_KeyAuthorization_14Fields tests that a 14-field RLP list where
// field 13 is a list (keyAuthorization without signature) is handled correctly.
func TestDeserialize_KeyAuthorization_14Fields(t *testing.T) {
	keyAuthTuple := []interface{}{
		common.HexToAddress("0xabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd").Bytes(),
		[]byte{0x01, 0x02, 0x03},
	}

	serialized := encodeToHex(t, buildKeyAuthRLPList(keyAuthTuple, nil))

	tx, err := Deserialize(serialized)
	require.NoError(t, err)

	assert.NotNil(t, tx.KeyAuthorization, "KeyAuthorization should be present")
	assert.Nil(t, tx.Signature, "Signature should be nil when only 14 fields with keyAuth")
}

// TestDeserialize_FieldCount_Rejected tests that unsupported field counts are rejected.
func TestDeserialize_FieldCount_Rejected(t *testing.T) {
	tests := []struct {
		name       string
		fieldCount int
		wantErr    string
	}{
		{
			name:       "12_fields_rejected",
			fieldCount: 12,
			wantErr:    "expected 13, 14, or 15 fields, got 12",
		},
		{
			name:       "16_fields_rejected",
			fieldCount: 16,
			wantErr:    "expected 13, 14, or 15 fields, got 16",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rlpList := make([]interface{}, tt.fieldCount)
			for i := range rlpList {
				rlpList[i] = []byte{}
			}
			if tt.fieldCount > 4 {
				rlpList[4] = []interface{}{} // calls must be a list
			}
			if tt.fieldCount > 5 {
				rlpList[5] = []interface{}{} // accessList must be a list
			}
			if tt.fieldCount > 12 {
				rlpList[12] = []interface{}{} // authorizationList must be a list
			}

			serialized := encodeToHex(t, rlpList)

			_, err := Deserialize(serialized)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// TestDeserialize_KeyAuthorization_Roundtrip verifies that 15-field transactions
// survive a full serialize -> deserialize -> serialize cycle with identical bytes.
func TestDeserialize_KeyAuthorization_Roundtrip(t *testing.T) {
	sigEnvelope, _, _ := makeSecp256k1Envelope()
	keyAuthTuple := []interface{}{
		common.HexToAddress("0xabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd").Bytes(),
		[]byte{0x01, 0x02, 0x03},
		big.NewInt(9999999).Bytes(),
	}

	original := encodeToHex(t, buildKeyAuthRLPList(keyAuthTuple, sigEnvelope))

	tx1, err := Deserialize(original)
	require.NoError(t, err)
	require.NotNil(t, tx1.KeyAuthorization)
	require.NotNil(t, tx1.Signature)

	serialized1, err := Serialize(tx1, nil)
	require.NoError(t, err)

	tx2, err := Deserialize(serialized1)
	require.NoError(t, err)

	// Core fields preserved
	assert.Equal(t, 0, tx1.ChainID.Cmp(tx2.ChainID), "ChainID mismatch after roundtrip")
	assert.Equal(t, tx1.Gas, tx2.Gas, "Gas mismatch after roundtrip")
	assert.Equal(t, tx1.Nonce, tx2.Nonce, "Nonce mismatch after roundtrip")

	// keyAuthorization preserved
	require.NotNil(t, tx2.KeyAuthorization, "KeyAuthorization lost after roundtrip")
	keyAuth1, _ := tx1.KeyAuthorization.([]interface{})
	keyAuth2, _ := tx2.KeyAuthorization.([]interface{})
	assert.Equal(t, len(keyAuth1), len(keyAuth2), "KeyAuthorization tuple length mismatch")

	// Signature preserved
	require.NotNil(t, tx2.Signature, "Signature lost after roundtrip")
	assert.Equal(t, 0, tx1.Signature.Signature.R.Cmp(tx2.Signature.Signature.R), "Signature R mismatch")
	assert.Equal(t, 0, tx1.Signature.Signature.S.Cmp(tx2.Signature.Signature.S), "Signature S mismatch")

	// Double roundtrip produces identical bytes
	serialized2, err := Serialize(tx2, nil)
	require.NoError(t, err)
	assert.Equal(t, serialized1, serialized2, "Double roundtrip should produce identical bytes")
}
