package transaction

import (
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/tempoxyz/tempo-go/pkg/signer"
)

func TestSerialize(t *testing.T) {
	tests := []struct {
		name    string
		tx      *Tx
		opts    *SerializeOptions
		want    string
		wantErr bool
	}{
		{
			name: "minimal transaction",
			tx: &Tx{
				ChainID:              big.NewInt(42424),
				MaxPriorityFeePerGas: big.NewInt(1000000),
				MaxFeePerGas:         big.NewInt(2000000),
				Gas:                  21000,
				Calls: []Call{
					{
						To:    addrPtr(common.HexToAddress("0x1234567890123456789012345678901234567890")),
						Value: big.NewInt(1000000000000000000), // 1 ETH
						Data:  []byte{},
					},
				},
				AccessList:        AccessList{},
				NonceKey:          big.NewInt(0),
				Nonce:             1,
				ValidBefore:       0,
				ValidAfter:        0,
				FeeToken:          common.HexToAddress("0x20c0000000000000000000000000000000000001"),
				Signature:         nil,
				FeePayerSignature: nil,
			},
			opts: nil,
			// Should start with 0x76
			want: "0x76",
		},
		{
			name: "transaction with fee payer format",
			tx: &Tx{
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
			},
			opts: &SerializeOptions{
				Format: FormatFeePayer,
				Sender: common.HexToAddress("0xabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"),
			},
			// Should start with 0x78
			want: "0x78",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Serialize(tt.tx, tt.opts)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.True(t, strings.HasPrefix(got, tt.want), "Serialize() = %v, want prefix %v", got[:4], tt.want)
			assert.True(t, strings.HasPrefix(got, "0x"), "Serialize() result doesn't start with 0x: %v", got[:4])
		})
	}
}

func TestSerializeForSigning(t *testing.T) {
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
		Signature:         signer.NewSignatureEnvelope(big.NewInt(123), big.NewInt(456), 0),
		FeePayerSignature: signer.NewSignature(big.NewInt(789), big.NewInt(101), 1),
	}

	got, err := SerializeForSigning(tx)
	assert.NoError(t, err)
	assert.True(t, strings.HasPrefix(got, "0x76"), "SerializeForSigning() = %v, want prefix 0x76", got[:4])

	deserialized, err := Deserialize(got)
	assert.NoError(t, err)
	assert.Nil(t, deserialized.Signature, "SerializeForSigning() should not include sender signature")
	assert.Nil(t, deserialized.FeePayerSignature, "SerializeForSigning() should not include fee payer signature")
}

func TestSerializeForFeePayerSigning(t *testing.T) {
	sender := common.HexToAddress("0xabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd")

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
		Signature:         signer.NewSignatureEnvelope(big.NewInt(123), big.NewInt(456), 0),
		FeePayerSignature: signer.NewSignature(big.NewInt(789), big.NewInt(101), 1),
	}

	got, err := SerializeForFeePayerSigning(tx, sender)
	assert.NoError(t, err)
	assert.True(t, strings.HasPrefix(got, "0x78"), "SerializeForFeePayerSigning() = %v, want prefix 0x78", got[:4])
}

func TestDeserialize(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    *Tx
		wantErr bool
	}{
		{
			name:    "invalid prefix",
			input:   "0x02f86b0180...",
			wantErr: true,
		},
		{
			name:    "missing 0x76 prefix",
			input:   "0x01f86b0180...",
			wantErr: true,
		},
		{
			name:    "empty data",
			input:   "",
			wantErr: true,
		},
		{
			name:    "malformed hex",
			input:   "0x76zzz",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Deserialize(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, got)
			}
		})
	}
}

func TestDeserializeCalls(t *testing.T) {
	tests := []struct {
		name    string
		input   []interface{}
		want    []Call
		wantErr bool
	}{
		{
			name:  "empty calls",
			input: []interface{}{},
			want:  []Call{},
		},
		{
			name: "single call with all fields",
			input: []interface{}{
				[]interface{}{
					common.HexToAddress("0x1234567890123456789012345678901234567890").Bytes(),
					big.NewInt(1000000).Bytes(),
					[]byte{0xde, 0xad, 0xbe, 0xef},
				},
			},
			want: []Call{
				{
					To:    addrPtr(common.HexToAddress("0x1234567890123456789012345678901234567890")),
					Value: big.NewInt(1000000),
					Data:  []byte{0xde, 0xad, 0xbe, 0xef},
				},
			},
		},
		{
			name: "multiple calls",
			input: []interface{}{
				[]interface{}{
					common.HexToAddress("0x1111111111111111111111111111111111111111").Bytes(),
					big.NewInt(100).Bytes(),
					[]byte{},
				},
				[]interface{}{
					common.HexToAddress("0x2222222222222222222222222222222222222222").Bytes(),
					big.NewInt(200).Bytes(),
					[]byte{0xaa, 0xbb},
				},
			},
			want: []Call{
				{
					To:    addrPtr(common.HexToAddress("0x1111111111111111111111111111111111111111")),
					Value: big.NewInt(100),
					Data:  []byte{},
				},
				{
					To:    addrPtr(common.HexToAddress("0x2222222222222222222222222222222222222222")),
					Value: big.NewInt(200),
					Data:  []byte{0xaa, 0xbb},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeCalls(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Len(t, got, len(tt.want))
			assert.True(t, cmp.Equal(tt.want, got, cmpOpts...), "decodeCalls() mismatch: %s", cmp.Diff(tt.want, got, cmpOpts...))
		})
	}
}

func TestDecodeAccessList(t *testing.T) {
	tests := []struct {
		name    string
		input   []interface{}
		want    AccessList
		wantErr bool
	}{
		{
			name:  "empty access list",
			input: []interface{}{},
			want:  AccessList{},
		},
		{
			name: "single entry with storage keys",
			input: []interface{}{
				[]interface{}{
					common.HexToAddress("0x1234567890123456789012345678901234567890").Bytes(),
					[]interface{}{
						common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001").Bytes(),
						common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000002").Bytes(),
					},
				},
			},
			want: AccessList{
				{
					Address: common.HexToAddress("0x1234567890123456789012345678901234567890"),
					StorageKeys: []common.Hash{
						common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001"),
						common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000002"),
					},
				},
			},
		},
		{
			name: "entry with no storage keys",
			input: []interface{}{
				[]interface{}{
					common.HexToAddress("0x1234567890123456789012345678901234567890").Bytes(),
					[]interface{}{},
				},
			},
			want: AccessList{
				{
					Address:     common.HexToAddress("0x1234567890123456789012345678901234567890"),
					StorageKeys: []common.Hash{},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeAccessList(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Len(t, got, len(tt.want))
			for i := range got {
				assert.Equal(t, tt.want[i].Address, got[i].Address, "decodeAccessList() entry %d address mismatch", i)
				assert.Len(t, got[i].StorageKeys, len(tt.want[i].StorageKeys), "decodeAccessList() entry %d storage keys length mismatch", i)
			}
		})
	}
}

func TestDecodeSignature(t *testing.T) {
	tests := []struct {
		name    string
		input   []interface{}
		want    *signer.Signature
		wantErr bool
	}{
		{
			name: "valid signature",
			input: []interface{}{
				[]byte{0},
				big.NewInt(12345).Bytes(),
				big.NewInt(67890).Bytes(),
			},
			want: signer.NewSignature(big.NewInt(12345), big.NewInt(67890), 0),
		},
		{
			name: "signature with yParity = 1",
			input: []interface{}{
				[]byte{1},
				big.NewInt(12345).Bytes(),
				big.NewInt(67890).Bytes(),
			},
			want: signer.NewSignature(big.NewInt(12345), big.NewInt(67890), 1),
		},
		{
			name: "invalid - wrong length",
			input: []interface{}{
				[]byte{0},
				big.NewInt(12345).Bytes(),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeSignature(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want.YParity, got.YParity)
			assert.Equal(t, 0, got.R.Cmp(tt.want.R))
			assert.Equal(t, 0, got.S.Cmp(tt.want.S))
		})
	}
}

func TestRoundtrip(t *testing.T) {
	tests := []struct {
		name string
		tx   *Tx
	}{
		{
			name: "minimal transaction",
			tx: &Tx{
				ChainID:              big.NewInt(42424),
				MaxPriorityFeePerGas: big.NewInt(1000000),
				MaxFeePerGas:         big.NewInt(2000000),
				Gas:                  21000,
				Calls: []Call{
					{
						To:    addrPtr(common.HexToAddress("0x1234567890123456789012345678901234567890")),
						Value: big.NewInt(1000000000000000000),
						Data:  []byte{},
					},
				},
				AccessList:        AccessList{},
				NonceKey:          big.NewInt(0),
				Nonce:             1,
				ValidBefore:       0,
				ValidAfter:        0,
				FeeToken:          common.HexToAddress("0x20c0000000000000000000000000000000000001"),
				Signature:         nil,
				FeePayerSignature: nil,
			},
		},
		{
			name: "transaction with all fields",
			tx: &Tx{
				ChainID:              big.NewInt(42424),
				MaxPriorityFeePerGas: big.NewInt(1000000),
				MaxFeePerGas:         big.NewInt(2000000),
				Gas:                  21000,
				Calls: []Call{
					{
						To:    addrPtr(common.HexToAddress("0x1234567890123456789012345678901234567890")),
						Value: big.NewInt(1000000000000000000),
						Data:  []byte{0xde, 0xad, 0xbe, 0xef},
					},
				},
				AccessList: AccessList{
					{
						Address: common.HexToAddress("0xabcd1234abcd1234abcd1234abcd1234abcd1234"),
						StorageKeys: []common.Hash{
							common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001"),
						},
					},
				},
				NonceKey:    big.NewInt(123),
				Nonce:       456,
				ValidBefore: 1700000000,
				ValidAfter:  1600000000,
				FeeToken:    common.HexToAddress("0x20c0000000000000000000000000000000000001"),
				Signature: signer.NewSignatureEnvelope(
					hexToBigInt("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
					hexToBigInt("0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"),
					0,
				),
				FeePayerSignature: nil,
			},
		},
		{
			name: "transaction with multiple calls",
			tx: &Tx{
				ChainID:              big.NewInt(42424),
				MaxPriorityFeePerGas: big.NewInt(1000000),
				MaxFeePerGas:         big.NewInt(2000000),
				Gas:                  100000,
				Calls: []Call{
					{
						To:    addrPtr(common.HexToAddress("0x1111111111111111111111111111111111111111")),
						Value: big.NewInt(1000),
						Data:  []byte{},
					},
					{
						To:    addrPtr(common.HexToAddress("0x2222222222222222222222222222222222222222")),
						Value: big.NewInt(2000),
						Data:  []byte{0xaa, 0xbb},
					},
					{
						To:    addrPtr(common.HexToAddress("0x3333333333333333333333333333333333333333")),
						Value: big.NewInt(3000),
						Data:  []byte{0xcc, 0xdd, 0xee},
					},
				},
				AccessList:        AccessList{},
				NonceKey:          big.NewInt(0),
				Nonce:             1,
				ValidBefore:       0,
				ValidAfter:        0,
				FeeToken:          common.HexToAddress("0x20c0000000000000000000000000000000000001"),
				Signature:         nil,
				FeePayerSignature: nil,
			},
		},
		{
			name: "transaction with dual signatures",
			tx: &Tx{
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
				AccessList:  AccessList{},
				NonceKey:    big.NewInt(0),
				Nonce:       1,
				ValidBefore: 0,
				ValidAfter:  0,
				FeeToken:    common.HexToAddress("0x20c0000000000000000000000000000000000001"),
				Signature: signer.NewSignatureEnvelope(
					big.NewInt(12345),
					big.NewInt(67890),
					0,
				),
				FeePayerSignature: signer.NewSignature(
					big.NewInt(99999),
					big.NewInt(88888),
					1,
				),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serialized, err := Serialize(tt.tx, nil)
			assert.NoError(t, err)

			deserialized, err := Deserialize(serialized)
			assert.NoError(t, err)
			assert.True(t, cmp.Equal(tt.tx, deserialized, cmpOpts...), "Roundtrip failed: %s", cmp.Diff(tt.tx, deserialized, cmpOpts...))

			// == roundtrip again ==

			serialized2, err := Serialize(deserialized, nil)
			assert.NoError(t, err)
			assert.Equal(t, serialized, serialized2)
		})
	}
}

// TestRoundtripWithOptions tests roundtrip with different serialization options.
func TestRoundtripWithOptions(t *testing.T) {
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
		AccessList:  AccessList{},
		NonceKey:    big.NewInt(0),
		Nonce:       1,
		ValidBefore: 0,
		ValidAfter:  0,
		FeeToken:    common.HexToAddress("0x20c0000000000000000000000000000000000001"),
		Signature: signer.NewSignatureEnvelope(
			big.NewInt(12345),
			big.NewInt(67890),
			0,
		),
		FeePayerSignature: nil,
	}

	t.Run("normal format", func(t *testing.T) {
		serialized, err := Serialize(tx, &SerializeOptions{Format: FormatNormal})
		assert.NoError(t, err)

		deserialized, err := Deserialize(serialized)
		assert.NoError(t, err)
		assert.True(t, cmp.Equal(tx, deserialized, cmpOpts...), "Roundtrip with normal format failed: %s", cmp.Diff(tx, deserialized, cmpOpts...))
	})
}

// Helper functions

func hexToBigInt(s string) *big.Int {
	n := new(big.Int)
	n.SetString(s[2:], 16) // Remove 0x prefix
	return n
}
