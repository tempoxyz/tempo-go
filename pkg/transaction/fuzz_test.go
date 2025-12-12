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

func FuzzSerializeDeserializeRoundTrip(f *testing.F) {
	f.Add(
		uint64(42424),
		uint64(1000000000),
		uint64(2000000000),
		uint64(21000),
		uint64(0),
		uint64(1),
		uint64(0),
		uint64(0),
		[]byte{0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x90},
		[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		[]byte{0xaa, 0xbb, 0xcc},
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
		require.NoError(t, err)

		assert.Equal(t, 0, tx.ChainID.Cmp(deserializedTx.ChainID))
		assert.Equal(t, tx.Gas, deserializedTx.Gas)
		assert.Equal(t, tx.Nonce, deserializedTx.Nonce)
		assert.Equal(t, 0, tx.NonceKey.Cmp(deserializedTx.NonceKey))
		assert.Equal(t, tx.ValidBefore, deserializedTx.ValidBefore)
		assert.Equal(t, tx.ValidAfter, deserializedTx.ValidAfter)
		assert.Len(t, deserializedTx.Calls, len(tx.Calls))

		if len(tx.Calls) > 0 && len(deserializedTx.Calls) > 0 {
			assert.Equal(t, 0, tx.Calls[0].Value.Cmp(deserializedTx.Calls[0].Value))
			assert.True(t, bytes.Equal(tx.Calls[0].Data, deserializedTx.Calls[0].Data))
		}
	})
}

func FuzzDeserializeMalformed(f *testing.F) {
	f.Add([]byte("0x76"))
	f.Add([]byte("0x78"))
	f.Add([]byte("0x00"))
	f.Add([]byte{})
	f.Add([]byte("76f83b82a5e880808094123456789012345678901234567890123456789080c0808080808080c0"))
	f.Add([]byte("0x76f83b82a5e880808094123456789012345678901234567890123456789080c0808080808080c0"))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Deserialize(string(data))
	})
}

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

		// grab 20 bytes to common.Address
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
		require.NoError(t, err)

		deserializedTx, err := Deserialize(serialized)
		require.NoError(t, err)

		recoveredAddr, err := VerifySignature(deserializedTx)
		require.NoError(t, err)

		assert.Equal(t, sgn.Address(), recoveredAddr)
	})
}
