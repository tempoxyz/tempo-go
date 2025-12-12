package signer

import (
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
)

// test private keys -- please don't use these in production! they are technically valid.
// keys are pulled from `anvil` using default seed
const (
	testPrivateKey1 = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
	testPrivateKey2 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
)

func TestNewSigner(t *testing.T) {
	tests := []struct {
		name       string
		privateKey string
		wantErr    bool
		wantAddr   string
	}{
		{
			name:       "valid key with 0x prefix",
			privateKey: testPrivateKey1,
			wantErr:    false,
			wantAddr:   "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		},
		{
			name:       "valid key without 0x prefix",
			privateKey: testPrivateKey1[2:],
			wantErr:    false,
			wantAddr:   "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		},
		{
			name:       "different key",
			privateKey: testPrivateKey2,
			wantErr:    false,
			wantAddr:   "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		},
		{
			name:       "invalid hex",
			privateKey: "0xzzz",
			wantErr:    true,
		},
		{
			name:       "empty string",
			privateKey: "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewSigner(tt.privateKey)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.wantAddr, got.Address().Hex())
		})
	}
}

func TestSigner_Sign(t *testing.T) {
	sgn, err := NewSigner(testPrivateKey1)
	assert.NoError(t, err)

	testHash := crypto.Keccak256Hash([]byte("test message"))

	sig, err := sgn.Sign(testHash)
	assert.NoError(t, err)
	assert.NotNil(t, sig.R)
	assert.NotNil(t, sig.S)
	assert.LessOrEqual(t, sig.YParity, uint8(1))

	expectedV := uint8(27 + sig.YParity)
	assert.Equal(t, expectedV, sig.V())
}

func TestSigner_SignData(t *testing.T) {
	sgn, err := NewSigner(testPrivateKey1)
	assert.NoError(t, err)

	testData := []byte("test message")

	sig, err := sgn.SignData(testData)
	assert.NoError(t, err)
	assert.NotNil(t, sig.R)
	assert.NotNil(t, sig.S)

	testHash := crypto.Keccak256Hash(testData)
	sig2, err := sgn.Sign(testHash)
	assert.NoError(t, err)

	assert.Equal(t, 0, sig.R.Cmp(sig2.R))
	assert.Equal(t, 0, sig.S.Cmp(sig2.S))
	assert.Equal(t, sig.YParity, sig2.YParity)
}

func TestRecoverAddress(t *testing.T) {
	sgn, err := NewSigner(testPrivateKey1)
	assert.NoError(t, err)

	testHash := crypto.Keccak256Hash([]byte("test message"))

	sig, err := sgn.Sign(testHash)
	assert.NoError(t, err)

	recoveredAddr, err := RecoverAddress(testHash, sig)
	assert.NoError(t, err)

	assert.Equal(t, sgn.Address(), recoveredAddr)
}

func TestRecoverAddress_InvalidSignatures(t *testing.T) {
	big33Bytes := new(big.Int).Lsh(big.NewInt(1), 256) // 2^256 requires 33 bytes

	tests := []struct {
		name       string
		sig        *Signature
		wantErr    bool
		wantErrStr string
	}{
		{
			name:       "nil signature",
			sig:        nil,
			wantErr:    true,
			wantErrStr: "signature is nil",
		},
		{
			name:       "nil R",
			sig:        &Signature{R: nil, S: big.NewInt(1), YParity: 0},
			wantErr:    true,
			wantErrStr: "nil",
		},
		{
			name:       "nil S",
			sig:        &Signature{R: big.NewInt(1), S: nil, YParity: 0},
			wantErr:    true,
			wantErrStr: "nil",
		},
		{
			name:       "nil R and S",
			sig:        &Signature{R: nil, S: nil, YParity: 0},
			wantErr:    true,
			wantErrStr: "nil",
		},
		{
			name:       "oversized R (33 bytes)",
			sig:        &Signature{R: big33Bytes, S: big.NewInt(1), YParity: 0},
			wantErr:    true,
			wantErrStr: "R exceeds",
		},
		{
			name:       "oversized S (33 bytes)",
			sig:        &Signature{R: big.NewInt(1), S: big33Bytes, YParity: 0},
			wantErr:    true,
			wantErrStr: "S exceeds",
		},
		{
			name:       "oversized R and S",
			sig:        &Signature{R: big33Bytes, S: big33Bytes, YParity: 0},
			wantErr:    true,
			wantErrStr: "R exceeds",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := RecoverAddress(common.Hash{}, tt.sig)
			if tt.wantErr {
				assert.Error(t, err)
				assert.True(t, errors.Is(err, ErrInvalidSignature))
				assert.Contains(t, err.Error(), tt.wantErrStr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
