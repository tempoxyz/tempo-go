package transaction

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/tempoxyz/tempo-go/pkg/signer"
)

// test private keys pull from `anvil` using default seed -- please don't use these in production! they are technically valid.
const (
	testSenderKey   = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
	testFeePayerKey = "0xecc3fe55647412647e5c6b657c496803b08ef956f927b7a821da298cfbdd9666"
)

func TestSignTransaction(t *testing.T) {
	senderSigner, err := signer.NewSigner(testSenderKey)
	assert.NoError(t, err)

	tx := &Tx{
		ChainID:              big.NewInt(42424),
		MaxPriorityFeePerGas: big.NewInt(1000000),
		MaxFeePerGas:         big.NewInt(2000000),
		Gas:                  21000,
		Calls: []Call{
			{
				To:    addrPtr(common.HexToAddress("0x1234567890123456789012345678901234567890")),
				Value: big.NewInt(1000000),
				Data:  []byte{},
			},
		},
		AccessList:        AccessList{},
		NonceKey:          big.NewInt(0),
		Nonce:             1,
		FeeToken:          common.HexToAddress("0x20c0000000000000000000000000000000000001"),
		Signature:         nil,
		FeePayerSignature: nil,
	}

	err = SignTransaction(tx, senderSigner)
	assert.NoError(t, err)

	assert.NotNil(t, tx.Signature, "SignTransaction() did not add signature")
	assert.Equal(t, SignatureTypeSecp256k1, tx.Signature.Type)
	assert.NotNil(t, tx.Signature.Signature.R, "SignTransaction() signature has nil R")
	assert.NotNil(t, tx.Signature.Signature.S, "SignTransaction() signature has nil S")
	assert.Equal(t, senderSigner.Address(), tx.From)
}

func TestAddFeePayerSignature(t *testing.T) {
	senderSigner, err := signer.NewSigner(testSenderKey)
	assert.NoError(t, err)

	feePayerSigner, err := signer.NewSigner(testFeePayerKey)
	assert.NoError(t, err)

	tx := &Tx{
		ChainID:              big.NewInt(42424),
		MaxPriorityFeePerGas: big.NewInt(1000000),
		MaxFeePerGas:         big.NewInt(2000000),
		Gas:                  21000,
		Calls: []Call{
			{
				To:    addrPtr(common.HexToAddress("0x1234567890123456789012345678901234567890")),
				Value: big.NewInt(1000000),
				Data:  []byte{},
			},
		},
		AccessList:        AccessList{},
		NonceKey:          big.NewInt(0),
		Nonce:             1,
		FeeToken:          common.HexToAddress("0x20c0000000000000000000000000000000000001"),
		Signature:         nil,
		FeePayerSignature: nil,
		AwaitingFeePayer:  true,
	}

	err = SignTransaction(tx, senderSigner)
	assert.NoError(t, err)

	err = AddFeePayerSignature(tx, feePayerSigner)
	assert.NoError(t, err)

	assert.NotNil(t, tx.FeePayerSignature, "AddFeePayerSignature() did not add fee payer signature")
	assert.NotNil(t, tx.FeePayerSignature.R, "AddFeePayerSignature() signature has nil R")
	assert.NotNil(t, tx.FeePayerSignature.S, "AddFeePayerSignature() signature has nil S")
}

func TestAddFeePayerSignature_NoSenderSignature(t *testing.T) {
	feePayerSigner, err := signer.NewSigner(testFeePayerKey)
	assert.NoError(t, err)

	tx := &Tx{
		ChainID:           big.NewInt(42424),
		Calls:             []Call{},
		Signature:         nil,
		FeePayerSignature: nil,
	}

	err = AddFeePayerSignature(tx, feePayerSigner)
	assert.Error(t, err, "AddFeePayerSignature() should fail when transaction has no sender signature")
}

func TestVerifySignature(t *testing.T) {
	senderSigner, err := signer.NewSigner(testSenderKey)
	assert.NoError(t, err)

	tx := &Tx{
		ChainID:              big.NewInt(42424),
		MaxPriorityFeePerGas: big.NewInt(1000000),
		MaxFeePerGas:         big.NewInt(2000000),
		Gas:                  21000,
		Calls: []Call{
			{
				To:    addrPtr(common.HexToAddress("0x1234567890123456789012345678901234567890")),
				Value: big.NewInt(1000000),
				Data:  []byte{},
			},
		},
		AccessList:        AccessList{},
		NonceKey:          big.NewInt(0),
		Nonce:             1,
		FeeToken:          common.HexToAddress("0x20c0000000000000000000000000000000000001"),
		Signature:         nil,
		FeePayerSignature: nil,
	}

	err = SignTransaction(tx, senderSigner)
	assert.NoError(t, err)

	recoveredSender, err := VerifySignature(tx)
	assert.NoError(t, err)
	assert.Equal(t, senderSigner.Address(), recoveredSender)
}

func TestVerifyFeePayerSignature(t *testing.T) {
	senderSigner, err := signer.NewSigner(testSenderKey)
	assert.NoError(t, err)

	feePayerSigner, err := signer.NewSigner(testFeePayerKey)
	assert.NoError(t, err)

	tx := &Tx{
		ChainID:              big.NewInt(42424),
		MaxPriorityFeePerGas: big.NewInt(1000000),
		MaxFeePerGas:         big.NewInt(2000000),
		Gas:                  21000,
		Calls: []Call{
			{
				To:    addrPtr(common.HexToAddress("0x1234567890123456789012345678901234567890")),
				Value: big.NewInt(1000000),
				Data:  []byte{},
			},
		},
		AccessList:        AccessList{},
		NonceKey:          big.NewInt(0),
		Nonce:             1,
		FeeToken:          common.HexToAddress("0x20c0000000000000000000000000000000000001"),
		Signature:         nil,
		FeePayerSignature: nil,
		AwaitingFeePayer:  true,
	}

	err = SignTransaction(tx, senderSigner)
	assert.NoError(t, err)

	err = AddFeePayerSignature(tx, feePayerSigner)
	assert.NoError(t, err)

	recoveredFeePayer, err := VerifyFeePayerSignature(tx, senderSigner.Address())
	assert.NoError(t, err)
	assert.Equal(t, feePayerSigner.Address(), recoveredFeePayer)
}

func TestVerifyDualSignatures(t *testing.T) {
	senderSigner, err := signer.NewSigner(testSenderKey)
	assert.NoError(t, err)

	feePayerSigner, err := signer.NewSigner(testFeePayerKey)
	assert.NoError(t, err)

	tx := &Tx{
		ChainID:              big.NewInt(42424),
		MaxPriorityFeePerGas: big.NewInt(1000000),
		MaxFeePerGas:         big.NewInt(2000000),
		Gas:                  21000,
		Calls: []Call{
			{
				To:    addrPtr(common.HexToAddress("0x1234567890123456789012345678901234567890")),
				Value: big.NewInt(1000000),
				Data:  []byte{},
			},
		},
		AccessList:        AccessList{},
		NonceKey:          big.NewInt(0),
		Nonce:             1,
		FeeToken:          common.HexToAddress("0x20c0000000000000000000000000000000000001"),
		Signature:         nil,
		FeePayerSignature: nil,
		AwaitingFeePayer:  true,
	}

	err = SignTransaction(tx, senderSigner)
	assert.NoError(t, err)

	err = AddFeePayerSignature(tx, feePayerSigner)
	assert.NoError(t, err)

	recoveredSender, recoveredFeePayer, err := VerifyDualSignatures(tx)
	assert.NoError(t, err)
	assert.Equal(t, senderSigner.Address(), recoveredSender)
	assert.Equal(t, feePayerSigner.Address(), recoveredFeePayer)
}

func TestSignAndRoundtrip(t *testing.T) {
	senderSigner, err := signer.NewSigner(testSenderKey)
	assert.NoError(t, err)

	feePayerSigner, err := signer.NewSigner(testFeePayerKey)
	assert.NoError(t, err)

	tx := &Tx{
		ChainID:              big.NewInt(42424),
		MaxPriorityFeePerGas: big.NewInt(1000000),
		MaxFeePerGas:         big.NewInt(2000000),
		Gas:                  21000,
		Calls: []Call{
			{
				To:    addrPtr(common.HexToAddress("0x1234567890123456789012345678901234567890")),
				Value: big.NewInt(1000000),
				Data:  []byte{0xde, 0xad, 0xbe, 0xef},
			},
		},
		AccessList:        AccessList{},
		NonceKey:          big.NewInt(0),
		Nonce:             1,
		FeeToken:          common.HexToAddress("0x20c0000000000000000000000000000000000001"),
		Signature:         nil,
		FeePayerSignature: nil,
		AwaitingFeePayer:  true,
	}

	err = SignTransaction(tx, senderSigner)
	assert.NoError(t, err)

	err = AddFeePayerSignature(tx, feePayerSigner)
	assert.NoError(t, err)

	serialized, err := Serialize(tx, nil)
	assert.NoError(t, err)

	deserialized, err := Deserialize(serialized)
	assert.NoError(t, err)

	recoveredSender, recoveredFeePayer, err := VerifyDualSignatures(deserialized)
	assert.NoError(t, err)
	assert.Equal(t, senderSigner.Address(), recoveredSender, "After roundtrip: sender mismatch")
	assert.Equal(t, feePayerSigner.Address(), recoveredFeePayer, "After roundtrip: feePayer mismatch")
}

// TestVerifySignature_AfterFeePayerSigns verifies that sender signature remains
// valid after fee payer signature is added. This is a critical test for sponsored
// transactions per the Tempo Transaction spec.
func TestVerifySignature_AfterFeePayerSigns(t *testing.T) {
	senderSigner, err := signer.NewSigner(testSenderKey)
	assert.NoError(t, err)

	feePayerSigner, err := signer.NewSigner(testFeePayerKey)
	assert.NoError(t, err)

	tx := &Tx{
		ChainID:              big.NewInt(42424),
		MaxPriorityFeePerGas: big.NewInt(1000000),
		MaxFeePerGas:         big.NewInt(2000000),
		Gas:                  21000,
		Calls: []Call{
			{
				To:    addrPtr(common.HexToAddress("0x1234567890123456789012345678901234567890")),
				Value: big.NewInt(1000000),
				Data:  []byte{},
			},
		},
		AccessList:       AccessList{},
		NonceKey:         big.NewInt(0),
		Nonce:            1,
		FeeToken:         common.HexToAddress("0x20c0000000000000000000000000000000000001"),
		AwaitingFeePayer: true,
	}

	err = SignTransaction(tx, senderSigner)
	assert.NoError(t, err)

	recoveredBeforeFeePayer, err := VerifySignature(tx)
	assert.NoError(t, err)
	assert.Equal(t, senderSigner.Address(), recoveredBeforeFeePayer)

	err = AddFeePayerSignature(tx, feePayerSigner)
	assert.NoError(t, err)

	recoveredAfterFeePayer, err := VerifySignature(tx)
	assert.NoError(t, err)
	assert.Equal(t, senderSigner.Address(), recoveredAfterFeePayer,
		"Sender signature should remain valid after fee payer signs")
}

// TestVerifySignature_UnsupportedType tests that non-secp256k1 signature types are rejected.
func TestVerifySignature_UnsupportedType(t *testing.T) {
	tests := []struct {
		name    string
		sigType string
	}{
		{"p256", SignatureTypeP256},
		{"webauthn", SignatureTypeWebAuthn},
		{"keychain", "keychain"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := &Tx{
				ChainID:  big.NewInt(42424),
				Gas:      21000,
				NonceKey: big.NewInt(0),
				Calls: []Call{
					{
						To:    addrPtr(common.HexToAddress("0x1234567890123456789012345678901234567890")),
						Value: big.NewInt(0),
						Data:  []byte{},
					},
				},
				Signature: &signer.SignatureEnvelope{
					Type:      tt.sigType,
					Signature: signer.NewSignature(big.NewInt(123), big.NewInt(456), 0),
				},
			}

			_, err := VerifySignature(tx)
			assert.Error(t, err)
			assert.ErrorIs(t, err, ErrUnsupportedSignatureType)
		})
	}
}

// TestVerifySignature_Secp256k1TypeValid tests that secp256k1 type (explicit and empty) works.
func TestVerifySignature_Secp256k1TypeValid(t *testing.T) {
	senderSigner, err := signer.NewSigner(testSenderKey)
	assert.NoError(t, err)

	tx := &Tx{
		ChainID:              big.NewInt(42424),
		MaxPriorityFeePerGas: big.NewInt(1000000),
		MaxFeePerGas:         big.NewInt(2000000),
		Gas:                  21000,
		Calls: []Call{
			{
				To:    addrPtr(common.HexToAddress("0x1234567890123456789012345678901234567890")),
				Value: big.NewInt(1000000),
				Data:  []byte{},
			},
		},
		NonceKey: big.NewInt(0),
		Nonce:    1,
	}

	err = SignTransaction(tx, senderSigner)
	assert.NoError(t, err)
	assert.Equal(t, SignatureTypeSecp256k1, tx.Signature.Type)

	recovered, err := VerifySignature(tx)
	assert.NoError(t, err)
	assert.Equal(t, senderSigner.Address(), recovered)

	tx.Signature.Type = ""
	recovered, err = VerifySignature(tx)
	assert.NoError(t, err)
	assert.Equal(t, senderSigner.Address(), recovered)
}
