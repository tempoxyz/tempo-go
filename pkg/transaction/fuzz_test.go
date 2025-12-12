package transaction

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tempoxyz/tempo-go/pkg/signer"
)

// FuzzSerializeDeserializeRoundTrip tests that serialize -> deserialize produces equivalent transactions.
func FuzzSerializeDeserializeRoundTrip(f *testing.F) {
	f.Add(
		uint64(42424),      // chainID
		uint64(1000000000), // maxPriorityFeePerGas
		uint64(2000000000), // maxFeePerGas
		uint64(21000),      // gas
		uint64(0),          // nonceKey
		uint64(1),          // nonce
		uint64(0),          // validBefore
		uint64(0),          // validAfter
		[]byte{0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x90}, // toAddress
		[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},                                                                         // value
		[]byte{0xaa, 0xbb, 0xcc}, // callData
	)

	f.Fuzz(func(t *testing.T,
		chainID uint64,
		maxPriorityFeePerGas uint64,
		maxFeePerGas uint64,
		gas uint64,
		nonceKey uint64,
		nonce uint64,
		validBefore uint64,
		validAfter uint64,
		toAddressBytes []byte,
		valueBytes []byte,
		callData []byte,
	) {
		if chainID == 0 || gas == 0 {
			return
		}

		var toAddress common.Address
		if len(toAddressBytes) >= 20 {
			copy(toAddress[:], toAddressBytes[:20])
		} else if len(toAddressBytes) > 0 {
			copy(toAddress[20-len(toAddressBytes):], toAddressBytes)
		}

		value := new(big.Int)
		if len(valueBytes) > 0 {
			value.SetBytes(valueBytes)
		}

		if len(callData) > 1024 {
			callData = callData[:1024]
		}

		tx := NewBuilder(big.NewInt(int64(chainID))).
			SetMaxPriorityFeePerGas(big.NewInt(int64(maxPriorityFeePerGas))).
			SetMaxFeePerGas(big.NewInt(int64(maxFeePerGas))).
			SetGas(gas).
			SetNonceKey(big.NewInt(int64(nonceKey))).
			SetNonce(nonce).
			SetValidBefore(validBefore).
			SetValidAfter(validAfter).
			AddCall(toAddress, value, callData).
			Build()

		serialized, err := Serialize(tx, nil)
		if err != nil {
			return
		}

		deserializedTx, err := Deserialize(serialized)
		require.NoError(t, err, "failed to deserialize valid serialization")

		assert.Equal(t, 0, tx.ChainID.Cmp(deserializedTx.ChainID), "ChainID mismatch")
		assert.Equal(t, tx.Gas, deserializedTx.Gas, "Gas mismatch")
		assert.Equal(t, tx.Nonce, deserializedTx.Nonce, "Nonce mismatch")
		assert.Equal(t, 0, tx.NonceKey.Cmp(deserializedTx.NonceKey), "NonceKey mismatch")
		assert.Equal(t, tx.ValidBefore, deserializedTx.ValidBefore, "ValidBefore mismatch")
		assert.Equal(t, tx.ValidAfter, deserializedTx.ValidAfter, "ValidAfter mismatch")
		assert.Len(t, deserializedTx.Calls, len(tx.Calls), "Calls length mismatch")

		if len(tx.Calls) > 0 && len(deserializedTx.Calls) > 0 {
			assert.Equal(t, 0, tx.Calls[0].Value.Cmp(deserializedTx.Calls[0].Value), "Call value mismatch")
			assert.True(t, bytes.Equal(tx.Calls[0].Data, deserializedTx.Calls[0].Data), "Call data mismatch")
		}
	})
}

// FuzzDeserializeMalformed tests that deserialization handles malformed input gracefully.
func FuzzDeserializeMalformed(f *testing.F) {
	f.Add([]byte("0x76"))
	f.Add([]byte("0x78"))
	f.Add([]byte("0x00"))
	f.Add([]byte{})
	f.Add([]byte("76f83b82a5e880808094123456789012345678901234567890123456789080c0808080808080c0"))
	f.Add([]byte("0x76f83b82a5e880808094123456789012345678901234567890123456789080c0808080808080c0"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should never panic, regardless of input
		_, _ = Deserialize(string(data))
	})
}

// FuzzSignedTransactionRoundTrip tests full sign -> serialize -> deserialize -> verify flow.
func FuzzSignedTransactionRoundTrip(f *testing.F) {
	f.Add(
		uint64(42424),
		uint64(21000),
		[]byte{0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x90},
		[]byte{0xaa, 0xbb},
	)

	f.Fuzz(func(t *testing.T,
		chainID uint64,
		gas uint64,
		toAddressBytes []byte,
		callData []byte,
	) {
		if chainID == 0 || gas == 0 {
			return
		}

		if len(callData) > 512 {
			callData = callData[:512]
		}

		var toAddress common.Address
		if len(toAddressBytes) >= 20 {
			copy(toAddress[:], toAddressBytes[:20])
		} else if len(toAddressBytes) > 0 {
			copy(toAddress[20-len(toAddressBytes):], toAddressBytes)
		}

		privateKey, err := crypto.GenerateKey()
		if err != nil {
			return
		}
		sgn := signer.NewSignerFromKey(privateKey)

		tx := NewBuilder(big.NewInt(int64(chainID))).
			SetGas(gas).
			AddCall(toAddress, big.NewInt(0), callData).
			Build()

		err = SignTransaction(tx, sgn)
		if err != nil {
			return
		}

		serialized, err := Serialize(tx, nil)
		require.NoError(t, err, "failed to serialize signed transaction")

		deserializedTx, err := Deserialize(serialized)
		require.NoError(t, err, "failed to deserialize signed transaction")

		recoveredAddr, err := VerifySignature(deserializedTx)
		require.NoError(t, err, "failed to verify signature")

		assert.Equal(t, sgn.Address(), recoveredAddr, "recovered address mismatch")
	})
}
