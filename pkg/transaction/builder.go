package transaction

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

// Builder provides a fluent interface for constructing transactions.
// This makes it easier to build complex transactions with many optional fields.
//
// Example usage:
//
//	tx := transaction.NewBuilder(big.NewInt(42424)).
//	    SetGas(100000).
//	    AddCall(toAddress, big.NewInt(0), data).
//	    SetFeeToken(transaction.AlphaUSDAddress).
//	    Build()
type Builder struct {
	tx *Tx
}

// NewBuilder creates a new transaction builder with the given chain ID.
func NewBuilder(chainID *big.Int) *Builder {
	return &Builder{
		tx: &Tx{
			ChainID:              chainID,
			MaxPriorityFeePerGas: big.NewInt(0),
			MaxFeePerGas:         big.NewInt(0),
			NonceKey:             big.NewInt(DefaultNonceKey),
		},
	}
}

// SetGas sets the gas limit for the transaction.
func (b *Builder) SetGas(gas uint64) *Builder {
	b.tx.Gas = gas
	return b
}

// SetMaxFeePerGas sets the maximum fee per gas.
func (b *Builder) SetMaxFeePerGas(maxFee *big.Int) *Builder {
	b.tx.MaxFeePerGas = maxFee
	return b
}

// SetMaxPriorityFeePerGas sets the maximum priority fee per gas.
func (b *Builder) SetMaxPriorityFeePerGas(maxPriorityFee *big.Int) *Builder {
	b.tx.MaxPriorityFeePerGas = maxPriorityFee
	return b
}

// SetNonce sets the nonce for the transaction.
func (b *Builder) SetNonce(nonce uint64) *Builder {
	b.tx.Nonce = nonce
	return b
}

// SetNonceKey sets the nonce key (sequence key) for 2D nonce system.
func (b *Builder) SetNonceKey(nonceKey *big.Int) *Builder {
	b.tx.NonceKey = nonceKey
	return b
}

// SetValidBefore sets the expiration timestamp for the transaction.
func (b *Builder) SetValidBefore(validBefore uint64) *Builder {
	b.tx.ValidBefore = validBefore
	return b
}

// SetValidAfter sets the activation timestamp for the transaction.
func (b *Builder) SetValidAfter(validAfter uint64) *Builder {
	b.tx.ValidAfter = validAfter
	return b
}

// SetFeeToken sets the token to use for paying gas fees.
func (b *Builder) SetFeeToken(token common.Address) *Builder {
	b.tx.FeeToken = token
	return b
}

// AddCall adds a call to the transaction.
// The to address can be nil for contract creation.
// Value and data can be nil, they will be converted to empty bytes/zero.
func (b *Builder) AddCall(to common.Address, value *big.Int, data []byte) *Builder {
	if value == nil {
		value = big.NewInt(0)
	}
	if data == nil {
		data = []byte{}
	}

	b.tx.Calls = append(b.tx.Calls, Call{
		To:    &to,
		Value: value,
		Data:  data,
	})
	return b
}

// AddContractCreation adds a contract creation call to the transaction.
func (b *Builder) AddContractCreation(value *big.Int, data []byte) *Builder {
	if value == nil {
		value = big.NewInt(0)
	}
	if data == nil {
		data = []byte{}
	}

	b.tx.Calls = append(b.tx.Calls, Call{
		To:    nil,
		Value: value,
		Data:  data,
	})
	return b
}

// AddAccessListEntry adds an entry to the access list.
func (b *Builder) AddAccessListEntry(address common.Address, storageKeys []common.Hash) *Builder {
	b.tx.AccessList = append(b.tx.AccessList, AccessTuple{
		Address:     address,
		StorageKeys: storageKeys,
	})
	return b
}

// SetSponsored marks this transaction as sponsored (awaiting a fee payer signature).
// Per the Tempo Transaction spec, sponsored transactions encode fee_token as empty
// and fee_payer_signature field as 0x00 in the sender's signing payload.
// This MUST be called before SignTransaction if a fee payer will be added later.
func (b *Builder) SetSponsored(sponsored bool) *Builder {
	b.tx.AwaitingFeePayer = sponsored
	return b
}

// Build returns the constructed transaction.
// Note: This does not validate the transaction. Call Validate() separately if needed.
func (b *Builder) Build() *Tx {
	return b.tx
}

// BuildAndValidate returns the constructed transaction after validating it.
// This is a convenience method that ensures the transaction is valid before returning.
// Returns an error if validation fails.
func (b *Builder) BuildAndValidate() (*Tx, error) {
	if err := b.tx.Validate(); err != nil {
		return nil, err
	}
	return b.tx, nil
}
