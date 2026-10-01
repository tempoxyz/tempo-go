package transaction

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
)

func TestTransactionBuilder_SetNonce(t *testing.T) {
	builder := NewBuilder(big.NewInt(42424))
	builder.SetNonce(42)

	tx := builder.Build()
	assert.Equal(t, uint64(42), tx.Nonce)
}

func TestTransactionBuilder_SetNonceKey(t *testing.T) {
	builder := NewBuilder(big.NewInt(42424))
	builder.SetNonceKey(big.NewInt(123))

	tx := builder.Build()
	assert.Equal(t, 0, tx.NonceKey.Cmp(big.NewInt(123)))
}

func TestTransactionBuilder_SetExpiringNonce(t *testing.T) {
	tx := NewBuilder(big.NewInt(42424)).
		SetExpiringNonce(101).
		SetValidBefore(1000000).
		Build()

	assert.True(t, tx.IsExpiringNonce())
	assert.Equal(t, 0, tx.NonceKey.Cmp(ExpiringNonceKey()))
	assert.Equal(t, uint64(101), tx.Nonce)
}

func TestTransactionBuilder_ExpiringNonceDiscriminatorsDiffer(t *testing.T) {
	build := func(nonce uint64) *Tx {
		return NewBuilder(big.NewInt(42424)).
			SetGas(100000).
			SetMaxFeePerGas(big.NewInt(20000000000)).
			SetExpiringNonce(nonce).
			SetValidBefore(1000000).
			AddCall(common.HexToAddress("0x1111111111111111111111111111111111111111"), big.NewInt(0), []byte{0x01}).
			Build()
	}

	first, err := SerializeForSigning(build(101))
	assert.NoError(t, err)
	second, err := SerializeForSigning(build(102))
	assert.NoError(t, err)
	assert.NotEqual(t, first, second)

	serialized, err := Serialize(build(102), nil)
	assert.NoError(t, err)
	decoded, err := Deserialize(serialized)
	assert.NoError(t, err)
	assert.True(t, decoded.IsExpiringNonce())
	assert.Equal(t, uint64(102), decoded.Nonce)
}

func TestTransactionBuilder_ExpiringNonceRequiresValidBefore(t *testing.T) {
	builder := NewBuilder(big.NewInt(42424)).
		SetGas(100000).
		SetExpiringNonce(101).
		AddCall(common.HexToAddress("0x1111111111111111111111111111111111111111"), big.NewInt(0), nil)

	_, err := builder.BuildAndValidate()
	assert.ErrorIs(t, err, ErrInvalidTransaction)
	assert.ErrorContains(t, err, "expiring nonce transaction must set validBefore")

	_, err = builder.SetValidBefore(1000000).BuildAndValidate()
	assert.NoError(t, err)
}

func TestExpiringNonceKeyReturnsCopy(t *testing.T) {
	ExpiringNonceKey().SetInt64(0)
	assert.Equal(t, 256, ExpiringNonceKey().BitLen())
}

func TestTransaction_IsExpiringNonce(t *testing.T) {
	assert.False(t, New().IsExpiringNonce())
	assert.False(t, (&Tx{}).IsExpiringNonce())
	assert.Equal(t, 256, ExpiringNonceKey().BitLen())
}

func TestTransactionBuilder_SetValidBefore(t *testing.T) {
	builder := NewBuilder(big.NewInt(42424))
	builder.SetValidBefore(1000000)

	tx := builder.Build()
	assert.Equal(t, uint64(1000000), tx.ValidBefore)
}

func TestTransactionBuilder_SetValidAfter(t *testing.T) {
	builder := NewBuilder(big.NewInt(42424))
	builder.SetValidAfter(500000)

	tx := builder.Build()
	assert.Equal(t, uint64(500000), tx.ValidAfter)
}

func TestTransactionBuilder_SetFeeToken(t *testing.T) {
	builder := NewBuilder(big.NewInt(42424))
	tokenAddress := common.HexToAddress("0x20c0000000000000000000000000000000000001")
	builder.SetFeeToken(tokenAddress)

	tx := builder.Build()
	assert.Equal(t, tokenAddress, tx.FeeToken)
}

func TestTransactionBuilder_AddContractCreation(t *testing.T) {
	builder := NewBuilder(big.NewInt(42424))
	value := big.NewInt(1000)
	data := []byte{0x60, 0x60, 0x60}

	builder.AddContractCreation(value, data)

	tx := builder.Build()
	assert.Len(t, tx.Calls, 1)
	assert.Nil(t, tx.Calls[0].To, "Contract creation should have nil To address")
	assert.Equal(t, 0, tx.Calls[0].Value.Cmp(value))
	assert.Equal(t, data, tx.Calls[0].Data)
}

func TestTransactionBuilder_AddContractCreation_NilValues(t *testing.T) {
	builder := NewBuilder(big.NewInt(42424))
	builder.AddContractCreation(nil, nil)

	tx := builder.Build()
	assert.Len(t, tx.Calls, 1)
	assert.Nil(t, tx.Calls[0].To)
	assert.Equal(t, 0, tx.Calls[0].Value.Cmp(big.NewInt(0)), "Nil value should default to 0")
	assert.Equal(t, []byte{}, tx.Calls[0].Data, "Nil data should default to empty bytes")
}

func TestTransactionBuilder_AddAccessListEntry(t *testing.T) {
	builder := NewBuilder(big.NewInt(42424))
	address := common.HexToAddress("0x1234567890123456789012345678901234567890")
	storageKeys := []common.Hash{
		common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001"),
		common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000002"),
	}

	builder.AddAccessListEntry(address, storageKeys)

	tx := builder.Build()
	assert.Len(t, tx.AccessList, 1)
	assert.Equal(t, address, tx.AccessList[0].Address)
	assert.Equal(t, storageKeys, tx.AccessList[0].StorageKeys)
}

func TestTransactionBuilder_BuildAndValidate_Success(t *testing.T) {
	builder := NewBuilder(big.NewInt(42424))
	builder.SetGas(21000)
	builder.AddCall(
		common.HexToAddress("0x1234567890123456789012345678901234567890"),
		big.NewInt(1000),
		[]byte{},
	)

	tx, err := builder.BuildAndValidate()
	assert.NoError(t, err)
	assert.NotNil(t, tx)
	assert.Equal(t, uint64(21000), tx.Gas)
}

func TestTransactionBuilder_BuildAndValidate_Failure(t *testing.T) {
	builder := NewBuilder(big.NewInt(42424))
	// Missing gas and calls - should fail validation

	tx, err := builder.BuildAndValidate()
	assert.Error(t, err)
	assert.Nil(t, tx)
	assert.ErrorIs(t, err, ErrInvalidTransaction)
}

func TestTransactionBuilder_ChainedCalls(t *testing.T) {
	recipient := common.HexToAddress("0x1234567890123456789012345678901234567890")
	feeToken := common.HexToAddress("0x20c0000000000000000000000000000000000001")

	tx := NewBuilder(big.NewInt(42424)).
		SetGas(100000).
		SetMaxFeePerGas(big.NewInt(2000000000)).
		SetMaxPriorityFeePerGas(big.NewInt(1000000000)).
		SetNonce(5).
		SetNonceKey(big.NewInt(0)).
		SetValidBefore(999999).
		SetValidAfter(100000).
		SetFeeToken(feeToken).
		AddCall(recipient, big.NewInt(500), []byte{0xaa, 0xbb}).
		AddAccessListEntry(recipient, []common.Hash{}).
		Build()

	assert.Equal(t, uint64(100000), tx.Gas)
	assert.Equal(t, 0, tx.MaxFeePerGas.Cmp(big.NewInt(2000000000)))
	assert.Equal(t, 0, tx.MaxPriorityFeePerGas.Cmp(big.NewInt(1000000000)))
	assert.Equal(t, uint64(5), tx.Nonce)
	assert.Equal(t, 0, tx.NonceKey.Cmp(big.NewInt(0)))
	assert.Equal(t, uint64(999999), tx.ValidBefore)
	assert.Equal(t, uint64(100000), tx.ValidAfter)
	assert.Equal(t, feeToken, tx.FeeToken)
	assert.Len(t, tx.Calls, 1)
	assert.Len(t, tx.AccessList, 1)
}

func TestTransactionBuilder_MultipleCallsAndAccessList(t *testing.T) {
	builder := NewBuilder(big.NewInt(42424))

	addr1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	addr2 := common.HexToAddress("0x2222222222222222222222222222222222222222")
	addr3 := common.HexToAddress("0x3333333333333333333333333333333333333333")

	builder.
		AddCall(addr1, big.NewInt(100), []byte{0x01}).
		AddCall(addr2, big.NewInt(200), []byte{0x02}).
		AddContractCreation(big.NewInt(300), []byte{0x03}).
		AddAccessListEntry(addr1, []common.Hash{common.HexToHash("0x01")}).
		AddAccessListEntry(addr3, []common.Hash{common.HexToHash("0x03")})

	tx := builder.Build()

	assert.Len(t, tx.Calls, 3, "Should have 3 calls")
	assert.Equal(t, addr1, *tx.Calls[0].To)
	assert.Equal(t, addr2, *tx.Calls[1].To)
	assert.Nil(t, tx.Calls[2].To, "Contract creation should have nil To")

	assert.Len(t, tx.AccessList, 2, "Should have 2 access list entries")
	assert.Equal(t, addr1, tx.AccessList[0].Address)
	assert.Equal(t, addr3, tx.AccessList[1].Address)
}
