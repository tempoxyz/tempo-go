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
