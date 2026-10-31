package transaction

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
)

func TestTransaction_Validate(t *testing.T) {
	tests := []struct {
		name    string
		tx      *Tx
		wantErr error
	}{
		{
			name: "valid transaction",
			tx: &Tx{
				ChainID:              big.NewInt(42424),
				MaxPriorityFeePerGas: big.NewInt(1000000000),
				MaxFeePerGas:         big.NewInt(2000000000),
				Gas:                  100000,
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
			},
			wantErr: nil,
		},
		{
			name: "missing chain ID",
			tx: &Tx{
				ChainID: nil,
				Gas:     100000,
				Calls: []Call{
					{
						To:    addrPtr(common.HexToAddress("0x1234567890123456789012345678901234567890")),
						Value: big.NewInt(0),
						Data:  []byte{},
					},
				},
				NonceKey: big.NewInt(0),
			},
			wantErr: ErrInvalidTransaction,
		},
		{
			name: "zero chain ID",
			tx: &Tx{
				ChainID: big.NewInt(0),
				Gas:     100000,
				Calls: []Call{
					{
						To:    addrPtr(common.HexToAddress("0x1234567890123456789012345678901234567890")),
						Value: big.NewInt(0),
						Data:  []byte{},
					},
				},
				NonceKey: big.NewInt(0),
			},
			wantErr: ErrInvalidTransaction,
		},
		{
			name: "missing gas",
			tx: &Tx{
				ChainID: big.NewInt(42424),
				Gas:     0,
				Calls: []Call{
					{
						To:    addrPtr(common.HexToAddress("0x1234567890123456789012345678901234567890")),
						Value: big.NewInt(0),
						Data:  []byte{},
					},
				},
				NonceKey: big.NewInt(0),
			},
			wantErr: ErrInvalidTransaction,
		},
		{
			name: "no calls",
			tx: &Tx{
				ChainID:  big.NewInt(42424),
				Gas:      100000,
				Calls:    []Call{},
				NonceKey: big.NewInt(0),
			},
			wantErr: ErrInvalidTransaction,
		},
		{
			name: "call with nil value",
			tx: &Tx{
				ChainID: big.NewInt(42424),
				Gas:     100000,
				Calls: []Call{
					{
						To:    addrPtr(common.HexToAddress("0x1234567890123456789012345678901234567890")),
						Value: nil,
						Data:  []byte{},
					},
				},
				NonceKey: big.NewInt(0),
			},
			wantErr: ErrInvalidTransaction,
		},
		{
			name: "missing nonce key",
			tx: &Tx{
				ChainID:  big.NewInt(42424),
				Gas:      100000,
				Calls:    []Call{{To: addrPtr(common.HexToAddress("0x1234567890123456789012345678901234567890")), Value: big.NewInt(0), Data: []byte{}}},
				NonceKey: nil,
			},
			wantErr: ErrInvalidTransaction,
		},
		{
			name: "multiple calls valid",
			tx: &Tx{
				ChainID:              big.NewInt(42424),
				MaxPriorityFeePerGas: big.NewInt(1000000000),
				MaxFeePerGas:         big.NewInt(2000000000),
				Gas:                  200000,
				Calls: []Call{
					{
						To:    addrPtr(common.HexToAddress("0x1111111111111111111111111111111111111111")),
						Value: big.NewInt(100),
						Data:  []byte{0x01, 0x02},
					},
					{
						To:    addrPtr(common.HexToAddress("0x2222222222222222222222222222222222222222")),
						Value: big.NewInt(200),
						Data:  []byte{0x03, 0x04},
					},
				},
				NonceKey: big.NewInt(1),
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.tx.Validate()
			if tt.wantErr != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestTransaction_Validate_FeesAndValidityWindow(t *testing.T) {
	base := func() *Tx {
		return &Tx{
			ChainID:              big.NewInt(42424),
			MaxPriorityFeePerGas: big.NewInt(1000000000),
			MaxFeePerGas:         big.NewInt(2000000000),
			Gas:                  100000,
			Calls: []Call{{
				To:    addrPtr(common.HexToAddress("0x1234567890123456789012345678901234567890")),
				Value: big.NewInt(0),
			}},
			NonceKey: big.NewInt(0),
		}
	}

	tests := []struct {
		name    string
		mutate  func(tx *Tx)
		wantErr bool
	}{
		{"tip equal to fee cap", func(tx *Tx) { tx.MaxPriorityFeePerGas = big.NewInt(2000000000) }, false},
		{"tip above fee cap", func(tx *Tx) { tx.MaxPriorityFeePerGas = big.NewInt(2000000001) }, true},
		{"tip set without fee cap (checked once a fee cap is set, as in ox)", func(tx *Tx) { tx.MaxFeePerGas = big.NewInt(0) }, false},
		{"validBefore after validAfter", func(tx *Tx) { tx.ValidAfter, tx.ValidBefore = 100, 101 }, false},
		{"equal validity window", func(tx *Tx) { tx.ValidAfter, tx.ValidBefore = 100, 100 }, true},
		{"inverted validity window", func(tx *Tx) { tx.ValidAfter, tx.ValidBefore = 200, 100 }, true},
		{"only validAfter", func(tx *Tx) { tx.ValidAfter = 200 }, false},
		{"only validBefore", func(tx *Tx) { tx.ValidBefore = 200 }, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := base()
			tt.mutate(tx)
			err := tx.Validate()
			if tt.wantErr {
				assert.ErrorIs(t, err, ErrInvalidTransaction)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
