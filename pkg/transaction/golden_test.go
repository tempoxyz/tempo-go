package transaction

import (
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tempoxyz/tempo-go/pkg/signer"
)

// TestTempoGoldenFormat tests compatibility with tempo.ts transaction format
// This was copied over from the tempo.ts repo
func TestTempoGoldenFormat(t *testing.T) {
	// Format: 0x76 + RLP + senderAddress + "feefeefeefee"
	clientTx := "0x76f87582a5bd808502cb417800825dc2dcdb9400000000000000000000000000000000000000008084deadbeefc0800b80808000c0b8417607a2e7bea757dc38093db971a7ec7537a690a698119d629b2eb6bb433315767a20aeb717b10285986bc22f0cbb7e9254a2a1f35d5c29ad5119e8b46e202ec41cd47b37BBC34fa57e9a67Ae7d0a1496edC88f04Bbfeefeefeefee"

	t.Run("Deserialize tempo.ts transaction", func(t *testing.T) {
		tx, err := Deserialize(clientTx)
		assert.NoError(t, err)
		assert.Equal(t, 0, tx.ChainID.Cmp(big.NewInt(42429)))
		assert.Equal(t, uint64(11), tx.Nonce)
		assert.Equal(t, uint64(24002), tx.Gas)
		assert.NotNil(t, tx.Signature, "Signature envelope is nil")
		assert.Equal(t, "secp256k1", tx.Signature.Type)

		expectedRStart := "7607a2e7bea757dc3809"
		actualRStart := tx.Signature.Signature.R.Text(16)[:20]
		assert.Equal(t, expectedRStart, actualRStart, "Signature R mismatch")

		assert.Nil(t, tx.FeePayerSignature, "Fee payer signature should be nil before adding")
	})

	t.Run("Add fee payer signature and serialize", func(t *testing.T) {
		tx, err := Deserialize(clientTx)
		assert.NoError(t, err)

		feePayerKey := "0xdd83cd66cd98801a07e0b7c1a5b02364b369e696da7c0ab444acffea5cca86fc"
		feePayerSigner, err := signer.NewSigner(feePayerKey)
		assert.NoError(t, err)

		err = AddFeePayerSignature(tx, feePayerSigner)
		assert.NoError(t, err)
		assert.NotNil(t, tx.FeePayerSignature, "Fee payer signature was not added")

		dualSigned, err := Serialize(tx, nil)
		assert.NoError(t, err)
		assert.True(t, strings.HasPrefix(dualSigned, "0x76"), "Serialized transaction should start with 0x76, got %s", dualSigned[:6])
		assert.Greater(t, len(dualSigned), len(clientTx)-52, "Dual-signed transaction should be longer")
	})

	t.Run("Verify signature envelope encoding format", func(t *testing.T) {
		tx, err := Deserialize(clientTx)
		assert.NoError(t, err)

		reserialized, err := Serialize(tx, nil)
		assert.NoError(t, err)
		assert.Contains(t, reserialized, "b841", "Expected signature envelope to be encoded as b841 (65-byte string). Serialized: %s", reserialized)
	})

	t.Run("Roundtrip: deserialize -> add fee payer -> serialize -> deserialize", func(t *testing.T) {
		tx1, err := Deserialize(clientTx)
		assert.NoError(t, err)

		feePayerKey := "0xdd83cd66cd98801a07e0b7c1a5b02364b369e696da7c0ab444acffea5cca86fc"
		feePayerSigner, err := signer.NewSigner(feePayerKey)
		assert.NoError(t, err)

		err = AddFeePayerSignature(tx1, feePayerSigner)
		assert.NoError(t, err)

		serialized, err := Serialize(tx1, nil)
		assert.NoError(t, err)

		tx2, err := Deserialize(serialized)
		assert.NoError(t, err)

		assert.Equal(t, 0, tx2.ChainID.Cmp(tx1.ChainID), "ChainID mismatch after roundtrip")
		assert.Equal(t, tx1.Nonce, tx2.Nonce, "Nonce mismatch after roundtrip")
		assert.NotNil(t, tx2.FeePayerSignature, "Fee payer signature lost after roundtrip")
		assert.NotNil(t, tx2.Signature, "Sender signature lost after roundtrip")
		assert.Equal(t, 0, tx1.Signature.Signature.R.Cmp(tx2.Signature.Signature.R), "Sender signature R mismatch after roundtrip")
		assert.Equal(t, 0, tx1.FeePayerSignature.R.Cmp(tx2.FeePayerSignature.R), "Fee payer signature R mismatch after roundtrip")
	})
}
