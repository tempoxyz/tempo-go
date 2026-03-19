package transaction

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tempoxyz/tempo-go/pkg/signer"
)

// TestSerialize_KeyAuthorization_FieldCount verifies that the serializer produces
// the correct number of RLP fields depending on whether KeyAuthorization is set.
func TestSerialize_KeyAuthorization_FieldCount(t *testing.T) {
	baseTx := func() *Tx {
		return &Tx{
			ChainID:              big.NewInt(42424),
			MaxPriorityFeePerGas: big.NewInt(1000000),
			MaxFeePerGas:         big.NewInt(2000000),
			Gas:                  21000,
			Calls: []Call{
				{
					To:    addrPtr(common.HexToAddress("0x1234567890123456789012345678901234567890")),
					Value: big.NewInt(0),
					Data:  []byte{},
				},
			},
			AccessList: AccessList{},
			NonceKey:   big.NewInt(0),
			Nonce:      1,
			FeeToken:   common.HexToAddress("0x20c0000000000000000000000000000000000001"),
			Signature: signer.NewSignatureEnvelope(
				big.NewInt(12345),
				big.NewInt(67890),
				0,
			),
		}
	}

	t.Run("without_key_authorization_produces_14_fields", func(t *testing.T) {
		tx := baseTx()

		serialized, err := Serialize(tx, nil)
		require.NoError(t, err)

		deserialized, err := Deserialize(serialized)
		require.NoError(t, err)

		assert.Nil(t, deserialized.KeyAuthorization, "KeyAuthorization should be absent")
		assert.NotNil(t, deserialized.Signature, "Signature should be present")
	})

	t.Run("with_key_authorization_produces_15_fields", func(t *testing.T) {
		tx := baseTx()
		tx.KeyAuthorization = []interface{}{
			common.HexToAddress("0xabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd").Bytes(),
			[]byte{0x01, 0x02, 0x03},
		}

		serialized, err := Serialize(tx, nil)
		require.NoError(t, err)

		deserialized, err := Deserialize(serialized)
		require.NoError(t, err)

		assert.NotNil(t, deserialized.KeyAuthorization, "KeyAuthorization should be present")
		assert.NotNil(t, deserialized.Signature, "Signature should be present")
	})
}

// TestSerialize_KeyAuthorization_FeePayerFlow verifies that keyAuthorization is
// preserved through the full fee payer co-signing pipeline:
// sign -> serialize -> deserialize -> addFeePayerSig -> serialize -> deserialize.
func TestSerialize_KeyAuthorization_FeePayerFlow(t *testing.T) {
	senderSigner, err := signer.NewSigner("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	require.NoError(t, err)
	feePayerSigner, err := signer.NewSigner("0xdd83cd66cd98801a07e0b7c1a5b02364b369e696da7c0ab444acffea5cca86fc")
	require.NoError(t, err)

	keyAuthTuple := []interface{}{
		common.HexToAddress("0xabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd").Bytes(),
		[]byte{0x01, 0x02, 0x03},
	}

	tx := NewBuilder(big.NewInt(42424)).
		SetGas(21000).
		AddCall(common.HexToAddress("0x1234567890123456789012345678901234567890"), big.NewInt(0), []byte{}).
		Build()
	tx.KeyAuthorization = keyAuthTuple

	// Step 1: Sender signs
	err = SignTransaction(tx, senderSigner)
	require.NoError(t, err)
	assert.NotNil(t, tx.KeyAuthorization, "KeyAuthorization should survive sender signing")

	// Step 2: Serialize (client sends to server)
	serialized, err := Serialize(tx, nil)
	require.NoError(t, err)

	// Step 3: Deserialize (server receives)
	txServer, err := Deserialize(serialized)
	require.NoError(t, err)
	assert.NotNil(t, txServer.KeyAuthorization, "KeyAuthorization should survive deserialization")

	// Step 4: Fee payer co-signs (server adds its signature)
	err = AddFeePayerSignature(txServer, feePayerSigner)
	require.NoError(t, err)
	assert.NotNil(t, txServer.KeyAuthorization, "KeyAuthorization should survive fee payer signing")

	// Step 5: Re-serialize (server broadcasts)
	reSerialized, err := Serialize(txServer, nil)
	require.NoError(t, err)

	// Step 6: Final deserialize to verify everything is intact
	txFinal, err := Deserialize(reSerialized)
	require.NoError(t, err)
	assert.NotNil(t, txFinal.KeyAuthorization, "KeyAuthorization should survive full fee payer flow")
	assert.NotNil(t, txFinal.Signature, "Sender signature should be present")
	assert.NotNil(t, txFinal.FeePayerSignature, "Fee payer signature should be present")
}
