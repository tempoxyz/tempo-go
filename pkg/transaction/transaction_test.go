package transaction

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/tempoxyz/tempo-go/pkg/signer"
)

func TestNewDefault(t *testing.T) {
	tx := NewDefault(42424)

	assert.NotNil(t, tx)
	assert.Equal(t, 0, tx.ChainID.Cmp(big.NewInt(42424)))
	assert.Equal(t, 0, tx.NonceKey.Cmp(big.NewInt(DefaultNonceKey)))
	assert.Equal(t, 0, tx.MaxPriorityFeePerGas.Cmp(big.NewInt(0)))
	assert.Equal(t, 0, tx.MaxFeePerGas.Cmp(big.NewInt(0)))
}

func TestTransaction_HasFeePayerSignature(t *testing.T) {
	t.Run("without fee payer signature", func(t *testing.T) {
		tx := New()
		assert.False(t, tx.HasFeePayerSignature())
	})

	t.Run("with fee payer signature", func(t *testing.T) {
		tx := New()
		tx.FeePayerSignature = &signer.Signature{
			R:       big.NewInt(123),
			S:       big.NewInt(456),
			YParity: 0,
		}
		assert.True(t, tx.HasFeePayerSignature())
	})
}

func TestTransaction_IsExpired(t *testing.T) {
	tests := []struct {
		name        string
		validBefore uint64
		currentTime uint64
		wantExpired bool
	}{
		{
			name:        "no expiration set - early time",
			validBefore: 0,
			currentTime: 1000,
			wantExpired: false,
		},
		{
			name:        "no expiration set - late time",
			validBefore: 0,
			currentTime: 999999,
			wantExpired: false,
		},
		{
			name:        "not expired - before ValidBefore",
			validBefore: 1000,
			currentTime: 500,
			wantExpired: false,
		},
		{
			name:        "not expired - just before ValidBefore",
			validBefore: 1000,
			currentTime: 999,
			wantExpired: false,
		},
		{
			name:        "expired at boundary",
			validBefore: 1000,
			currentTime: 1000,
			wantExpired: true,
		},
		{
			name:        "expired - just after ValidBefore",
			validBefore: 1000,
			currentTime: 1001,
			wantExpired: true,
		},
		{
			name:        "expired - long after ValidBefore",
			validBefore: 1000,
			currentTime: 9999,
			wantExpired: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := New()
			tx.ValidBefore = tt.validBefore

			result := tx.IsExpired(tt.currentTime)
			assert.Equal(t, tt.wantExpired, result)
		})
	}
}

func TestTransaction_IsActive(t *testing.T) {
	tests := []struct {
		name        string
		validAfter  uint64
		currentTime uint64
		wantActive  bool
	}{
		{
			name:        "no activation time - at zero",
			validAfter:  0,
			currentTime: 0,
			wantActive:  true,
		},
		{
			name:        "no activation time - early time",
			validAfter:  0,
			currentTime: 1000,
			wantActive:  true,
		},
		{
			name:        "no activation time - late time",
			validAfter:  0,
			currentTime: 999999,
			wantActive:  true,
		},
		{
			name:        "not active - at zero",
			validAfter:  1000,
			currentTime: 0,
			wantActive:  false,
		},
		{
			name:        "not active - just before ValidAfter",
			validAfter:  1000,
			currentTime: 999,
			wantActive:  false,
		},
		{
			name:        "active at boundary",
			validAfter:  1000,
			currentTime: 1000,
			wantActive:  true,
		},
		{
			name:        "active - just after ValidAfter",
			validAfter:  1000,
			currentTime: 1001,
			wantActive:  true,
		},
		{
			name:        "active - long after ValidAfter",
			validAfter:  1000,
			currentTime: 9999,
			wantActive:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := New()
			tx.ValidAfter = tt.validAfter

			result := tx.IsActive(tt.currentTime)
			assert.Equal(t, tt.wantActive, result)
		})
	}
}

func TestTransaction_String(t *testing.T) {
	t.Run("minimal transaction", func(t *testing.T) {
		tx := New()
		tx.ChainID = big.NewInt(42424)
		tx.Gas = 21000

		str := tx.String()
		assert.Contains(t, str, "Transaction")
		assert.Contains(t, str, "42424")
		assert.Contains(t, str, "21000")
		assert.Contains(t, str, "Calls: 0")
		assert.Contains(t, str, "From: not recovered")
		assert.Contains(t, str, "Signed: no")
		assert.Contains(t, str, "FeePayerSigned: no")
	})

	t.Run("transaction with from address", func(t *testing.T) {
		tx := New()
		tx.ChainID = big.NewInt(42424)
		tx.Gas = 21000
		tx.From = common.HexToAddress("0x1234567890123456789012345678901234567890")

		str := tx.String()
		assert.Contains(t, str, "From: 0x1234567890123456789012345678901234567890")
	})

	t.Run("transaction with signature", func(t *testing.T) {
		tx := New()
		tx.ChainID = big.NewInt(42424)
		tx.Gas = 21000
		tx.Signature = &signer.SignatureEnvelope{
			Type: "secp256k1",
			Signature: &signer.Signature{
				R:       big.NewInt(1),
				S:       big.NewInt(2),
				YParity: 0,
			},
		}

		str := tx.String()
		assert.Contains(t, str, "Signed: yes")
	})

	t.Run("transaction with fee payer signature", func(t *testing.T) {
		tx := New()
		tx.ChainID = big.NewInt(42424)
		tx.Gas = 21000
		tx.FeePayerSignature = &signer.Signature{
			R:       big.NewInt(3),
			S:       big.NewInt(4),
			YParity: 1,
		}

		str := tx.String()
		assert.Contains(t, str, "FeePayerSigned: yes")
	})

	t.Run("transaction with calls", func(t *testing.T) {
		tx := New()
		tx.ChainID = big.NewInt(42424)
		tx.Gas = 21000
		tx.Calls = []Call{{To: addrPtr(common.HexToAddress("0x1111")), Value: big.NewInt(0), Data: []byte{}}}

		str := tx.String()
		assert.Contains(t, str, "Calls: 1")
	})
}

func TestTransaction_Hash(t *testing.T) {
	t.Run("unsigned transaction fails", func(t *testing.T) {
		tx := NewDefault(42424)
		tx.Gas = 21000
		tx.Calls = []Call{{To: addrPtr(common.HexToAddress("0x1234")), Value: big.NewInt(0), Data: []byte{}}}

		hash, err := tx.Hash()
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrNoSignature)
		assert.Equal(t, common.Hash{}, hash)
	})

	t.Run("signed transaction succeeds", func(t *testing.T) {
		sgn, err := signer.NewSigner("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
		assert.NoError(t, err)

		tx := NewBuilder(big.NewInt(42424)).
			SetGas(21000).
			AddCall(common.HexToAddress("0x1234567890123456789012345678901234567890"), big.NewInt(0), []byte{}).
			Build()

		err = SignTransaction(tx, sgn)
		assert.NoError(t, err)

		hash, err := tx.Hash()
		assert.NoError(t, err)
		assert.NotEqual(t, common.Hash{}, hash, "Hash should not be empty")
	})

	t.Run("hash is deterministic", func(t *testing.T) {
		sgn, err := signer.NewSigner("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
		assert.NoError(t, err)

		tx := NewBuilder(big.NewInt(42424)).
			SetGas(21000).
			SetNonce(5).
			AddCall(common.HexToAddress("0x1234567890123456789012345678901234567890"), big.NewInt(1000), []byte{0xaa}).
			Build()

		err = SignTransaction(tx, sgn)
		assert.NoError(t, err)

		hash1, err := tx.Hash()
		assert.NoError(t, err)

		hash2, err := tx.Hash()
		assert.NoError(t, err)

		assert.Equal(t, hash1, hash2, "Hash should be deterministic")
	})
}

func TestTransaction_Clone(t *testing.T) {
	t.Run("clone basic fields", func(t *testing.T) {
		original := New()
		original.ChainID = big.NewInt(42424)
		original.MaxPriorityFeePerGas = big.NewInt(1000000)
		original.MaxFeePerGas = big.NewInt(2000000)
		original.Gas = 21000
		original.NonceKey = big.NewInt(0)
		original.Nonce = 5
		original.ValidBefore = 999999
		original.ValidAfter = 100000
		original.FeeToken = common.HexToAddress("0x20c0000000000000000000000000000000000001")
		original.From = common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")

		cloned := original.Clone()

		assert.Equal(t, 0, cloned.ChainID.Cmp(original.ChainID))
		assert.Equal(t, 0, cloned.MaxPriorityFeePerGas.Cmp(original.MaxPriorityFeePerGas))
		assert.Equal(t, 0, cloned.MaxFeePerGas.Cmp(original.MaxFeePerGas))
		assert.Equal(t, original.Gas, cloned.Gas)
		assert.Equal(t, 0, cloned.NonceKey.Cmp(original.NonceKey))
		assert.Equal(t, original.Nonce, cloned.Nonce)
		assert.Equal(t, original.ValidBefore, cloned.ValidBefore)
		assert.Equal(t, original.ValidAfter, cloned.ValidAfter)
		assert.Equal(t, original.FeeToken, cloned.FeeToken)
		assert.Equal(t, original.From, cloned.From)
	})

	t.Run("clone creates deep copy", func(t *testing.T) {
		original := New()
		original.ChainID = big.NewInt(42424)
		original.MaxFeePerGas = big.NewInt(1000000)

		cloned := original.Clone()

		// Modify original
		original.ChainID.SetInt64(99999)
		original.MaxFeePerGas.SetInt64(9999999)

		// Cloned should not be affected
		assert.Equal(t, 0, cloned.ChainID.Cmp(big.NewInt(42424)))
		assert.Equal(t, 0, cloned.MaxFeePerGas.Cmp(big.NewInt(1000000)))
	})

	t.Run("clone calls deeply", func(t *testing.T) {
		original := New()
		addr1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
		addr2 := common.HexToAddress("0x2222222222222222222222222222222222222222")

		original.Calls = []Call{
			{To: &addr1, Value: big.NewInt(100), Data: []byte{0xaa, 0xbb}},
			{To: &addr2, Value: big.NewInt(200), Data: []byte{0xcc}},
		}

		cloned := original.Clone()

		assert.Len(t, cloned.Calls, 2)
		assert.Equal(t, addr1, *cloned.Calls[0].To)
		assert.Equal(t, 0, cloned.Calls[0].Value.Cmp(big.NewInt(100)))
		assert.Equal(t, []byte{0xaa, 0xbb}, cloned.Calls[0].Data)

		// Modify original
		// Cloned should not be affected
		original.Calls[0].Value.SetInt64(999)
		original.Calls[0].Data[0] = 0xff

		assert.Equal(t, 0, cloned.Calls[0].Value.Cmp(big.NewInt(100)), "Cloned value should not change")
		assert.Equal(t, byte(0xaa), cloned.Calls[0].Data[0], "Cloned data should not change")
	})

	t.Run("clone nil To address", func(t *testing.T) {
		original := New()
		original.Calls = []Call{
			{To: nil, Value: big.NewInt(100), Data: []byte{0xaa}},
		}

		cloned := original.Clone()

		assert.Len(t, cloned.Calls, 1)
		assert.Nil(t, cloned.Calls[0].To, "Cloned call should have nil To for contract creation")
	})

	t.Run("clone access list deeply", func(t *testing.T) {
		original := New()
		addr := common.HexToAddress("0x1234567890123456789012345678901234567890")
		storageKey1 := common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001")
		storageKey2 := common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000002")

		original.AccessList = AccessList{
			{Address: addr, StorageKeys: []common.Hash{storageKey1, storageKey2}},
		}

		cloned := original.Clone()

		assert.Len(t, cloned.AccessList, 1)
		assert.Equal(t, addr, cloned.AccessList[0].Address)
		assert.Equal(t, []common.Hash{storageKey1, storageKey2}, cloned.AccessList[0].StorageKeys)

		// Modify original
		// Cloned should not be affected
		original.AccessList[0].StorageKeys[0] = common.HexToHash("0xff")

		assert.Equal(t, storageKey1, cloned.AccessList[0].StorageKeys[0], "Cloned storage keys should not change")
	})

	t.Run("clone does not copy signatures", func(t *testing.T) {
		original := New()
		original.Signature = &signer.SignatureEnvelope{
			Type: "secp256k1",
			Signature: &signer.Signature{
				R:       big.NewInt(123),
				S:       big.NewInt(456),
				YParity: 0,
			},
		}
		original.FeePayerSignature = &signer.Signature{
			R:       big.NewInt(789),
			S:       big.NewInt(101),
			YParity: 1,
		}

		cloned := original.Clone()

		assert.Nil(t, cloned.Signature, "Clone should not copy sender signature")
		assert.Nil(t, cloned.FeePayerSignature, "Clone should not copy fee payer signature")
	})

	t.Run("clone empty transaction", func(t *testing.T) {
		original := New()
		cloned := original.Clone()

		assert.NotNil(t, cloned)
		assert.Empty(t, cloned.Calls)
		assert.Empty(t, cloned.AccessList)
	})
}
