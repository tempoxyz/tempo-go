package transaction

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
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
	big33Bytes := new(big.Int).Lsh(big.NewInt(1), 256)
	max32Bytes := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))

	tests := []struct {
		name       string
		r          []byte
		s          []byte
		yParity    byte
		want       *signer.Signature
		wantErr    bool
		wantErrStr string
	}{
		{
			name:    "valid signature",
			r:       big.NewInt(12345).Bytes(),
			s:       big.NewInt(67890).Bytes(),
			yParity: 0,
			want:    signer.NewSignature(big.NewInt(12345), big.NewInt(67890), 0),
		},
		{
			name:    "signature with yParity = 1",
			r:       big.NewInt(12345).Bytes(),
			s:       big.NewInt(67890).Bytes(),
			yParity: 1,
			want:    signer.NewSignature(big.NewInt(12345), big.NewInt(67890), 1),
		},
		{
			name:    "empty R and S",
			r:       []byte{},
			s:       []byte{},
			yParity: 0,
			want:    signer.NewSignature(big.NewInt(0), big.NewInt(0), 0),
		},
		{
			name:    "max valid size (32 bytes)",
			r:       max32Bytes.Bytes(),
			s:       max32Bytes.Bytes(),
			yParity: 0,
			want:    signer.NewSignature(max32Bytes, max32Bytes, 0),
		},
		{
			name:       "oversized R (33 bytes)",
			r:          big33Bytes.Bytes(),
			s:          big.NewInt(1).Bytes(),
			yParity:    0,
			wantErr:    true,
			wantErrStr: "r exceeds maximum size",
		},
		{
			name:       "oversized S (33 bytes)",
			r:          big.NewInt(1).Bytes(),
			s:          big33Bytes.Bytes(),
			yParity:    0,
			wantErr:    true,
			wantErrStr: "s exceeds maximum size",
		},
		{
			name:       "oversized R and S",
			r:          big33Bytes.Bytes(),
			s:          big33Bytes.Bytes(),
			yParity:    0,
			wantErr:    true,
			wantErrStr: "r exceeds maximum size",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := []interface{}{
				[]byte{tt.yParity},
				tt.r,
				tt.s,
			}
			got, err := decodeSignature(input)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, got)
				assert.Contains(t, err.Error(), tt.wantErrStr)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want.YParity, got.YParity)
			assert.Equal(t, 0, got.R.Cmp(tt.want.R))
			assert.Equal(t, 0, got.S.Cmp(tt.want.S))
		})
	}
}

func TestDecodeSignature_InvalidTupleLength(t *testing.T) {
	input := []interface{}{
		[]byte{0},
		big.NewInt(12345).Bytes(),
	}
	got, err := decodeSignature(input)
	assert.Error(t, err)
	assert.Nil(t, got)
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

func TestDeserialize_OversizedSignature(t *testing.T) {
	big33Bytes := new(big.Int).Lsh(big.NewInt(1), 256) // 33 bytes

	tests := []struct {
		name       string
		r          []byte
		s          []byte
		wantErrStr string
	}{
		{
			name:       "oversized R in fee payer signature",
			r:          big33Bytes.Bytes(),
			s:          big.NewInt(1).Bytes(),
			wantErrStr: "r exceeds maximum size",
		},
		{
			name:       "oversized S in fee payer signature",
			r:          big.NewInt(1).Bytes(),
			s:          big33Bytes.Bytes(),
			wantErrStr: "s exceeds maximum size",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rlpList := []interface{}{
				big.NewInt(42424).Bytes(),   // chainId
				big.NewInt(1000000).Bytes(), // maxPriorityFeePerGas
				big.NewInt(2000000).Bytes(), // maxFeePerGas
				big.NewInt(21000).Bytes(),   // gas
				[]interface{}{ // calls
					[]interface{}{
						common.HexToAddress("0x1234567890123456789012345678901234567890").Bytes(),
						big.NewInt(1000000).Bytes(),
						[]byte{},
					},
				},
				[]interface{}{},       // accessList
				[]byte{},              // nonceKey
				big.NewInt(1).Bytes(), // nonce
				[]byte{},              // validBefore
				[]byte{},              // validAfter
				[]byte{},              // feeToken
				[]interface{}{ // fee payer signature
					[]byte{0},
					tt.r,
					tt.s,
				},
				[]interface{}{}, // authorizationList
			}

			rlpBytes, err := rlp.EncodeToBytes(rlpList)
			assert.NoError(t, err)

			serialized := "0x76" + hex.EncodeToString(rlpBytes)

			_, err = Deserialize(serialized)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErrStr)
		})
	}
}

// Helper functions

func hexToBigInt(s string) *big.Int {
	n := new(big.Int)
	n.SetString(s[2:], 16) // Remove 0x prefix
	return n
}

// TestSerializeForSigning_SponsoredTransaction verifies that sponsored transactions
// follow the Tempo Transaction spec (https://docs.tempo.xyz/protocol/transactions/spec-tempo-transaction):
// - fee_token is SKIPPED (encoded as 0x80/empty) when fee payer is involved
// - fee_payer_signature field uses 0x00 marker
// This allows the fee payer to specify the fee token without invalidating sender's signature.
func TestSerializeForSigning_SponsoredTransaction(t *testing.T) {
	feeToken := common.HexToAddress("0x20c0000000000000000000000000000000000001")

	t.Run("awaiting fee payer mode", func(t *testing.T) {
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
			FeeToken:         feeToken,
			AwaitingFeePayer: true,
		}

		serialized, err := SerializeForSigning(tx)
		assert.NoError(t, err)

		deserialized, err := Deserialize(serialized)
		assert.NoError(t, err)

		// Per Tempo spec: fee_token is SKIPPED in sender's signing payload when fee payer is involved
		assert.Equal(t, common.Address{}, deserialized.FeeToken, "Sponsored tx signing payload should skip fee token")
		// Per Tempo spec: when feePayerSignature will be present, sender signs with 0x00 marker
		assert.True(t, deserialized.AwaitingFeePayer, "Sponsored tx should have 0x00 marker (AwaitingFeePayer=true)")
	})

	t.Run("with fee payer signature present", func(t *testing.T) {
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
			FeeToken:          feeToken,
			FeePayerSignature: signer.NewSignature(big.NewInt(789), big.NewInt(101), 1),
		}

		serialized, err := SerializeForSigning(tx)
		assert.NoError(t, err)

		deserialized, err := Deserialize(serialized)
		assert.NoError(t, err)

		// Per Tempo spec: fee_token is SKIPPED in sender's signing payload when fee payer is involved
		assert.Equal(t, common.Address{}, deserialized.FeeToken, "Sponsored tx signing payload should skip fee token")
		// Per Tempo spec: when fee payer signature exists, the sender signed with 0x00 marker
		assert.True(t, deserialized.AwaitingFeePayer, "Sponsored tx should have 0x00 marker (AwaitingFeePayer=true)")
	})

	t.Run("non-sponsored transaction keeps fee token", func(t *testing.T) {
		feeToken := common.HexToAddress("0x20c0000000000000000000000000000000000001")
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
			FeeToken:         feeToken,
			AwaitingFeePayer: false,
		}

		serialized, err := SerializeForSigning(tx)
		assert.NoError(t, err)

		deserialized, err := Deserialize(serialized)
		assert.NoError(t, err)

		assert.Equal(t, feeToken, deserialized.FeeToken, "Non-sponsored tx should preserve fee token")
		assert.False(t, deserialized.AwaitingFeePayer, "Non-sponsored tx should not have awaiting fee payer marker")
	})
}

// buildKeyAuthRLPList constructs a raw RLP field list for testing keyAuthorization deserialization.
func buildKeyAuthRLPList(keyAuth []interface{}, sigEnvelope []byte) []interface{} {
	list := []interface{}{
		big.NewInt(42424).Bytes(),
		big.NewInt(1000000).Bytes(),
		big.NewInt(2000000).Bytes(),
		big.NewInt(21000).Bytes(),
		[]interface{}{
			[]interface{}{
				common.HexToAddress("0x1234567890123456789012345678901234567890").Bytes(),
				big.NewInt(1000000).Bytes(),
				[]byte{0xde, 0xad},
			},
		},
		[]interface{}{},
		[]byte{},
		big.NewInt(1).Bytes(),
		[]byte{},
		[]byte{},
		common.HexToAddress("0x20c0000000000000000000000000000000000001").Bytes(),
		[]byte{0x00},
		[]interface{}{},
	}
	if keyAuth != nil {
		list = append(list, keyAuth)
	}
	if sigEnvelope != nil {
		list = append(list, sigEnvelope)
	}
	return list
}

func encodeToHex(t *testing.T, rlpList []interface{}) string {
	t.Helper()
	rlpBytes, err := rlp.EncodeToBytes(rlpList)
	assert.NoError(t, err)
	return "0x76" + hex.EncodeToString(rlpBytes)
}

func makeSecp256k1Envelope() ([]byte, *big.Int, *big.Int) {
	r := hexToBigInt("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
	s := hexToBigInt("0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321")
	envelope := make([]byte, 65)
	copy(envelope[0:32], r.Bytes())
	copy(envelope[32:64], s.Bytes())
	envelope[64] = 0x00
	return envelope, r, s
}

func TestDeserialize_KeyAuthorization_15Fields(t *testing.T) {
	sigEnvelope, sigR, sigS := makeSecp256k1Envelope()
	keyAuthTuple := []interface{}{
		common.HexToAddress("0xabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd").Bytes(),
		[]byte{0x01, 0x02, 0x03},
		big.NewInt(9999999).Bytes(),
	}

	serialized := encodeToHex(t, buildKeyAuthRLPList(keyAuthTuple, sigEnvelope))

	tx, err := Deserialize(serialized)
	assert.NoError(t, err)

	assert.Equal(t, 0, tx.ChainID.Cmp(big.NewInt(42424)), "ChainID mismatch")
	assert.Equal(t, uint64(21000), tx.Gas, "Gas mismatch")
	assert.Equal(t, uint64(1), tx.Nonce, "Nonce mismatch")
	assert.True(t, tx.AwaitingFeePayer, "AwaitingFeePayer should be true (0x00 marker)")

	assert.NotNil(t, tx.KeyAuthorization, "KeyAuthorization should be parsed from field 13")
	assert.Len(t, tx.KeyAuthorization, 3, "KeyAuthorization tuple should have 3 elements")

	assert.NotNil(t, tx.Signature, "Signature should be parsed from field 14")
	assert.Equal(t, "secp256k1", tx.Signature.Type)
	assert.Equal(t, 0, tx.Signature.Signature.R.Cmp(sigR), "Signature R mismatch")
	assert.Equal(t, 0, tx.Signature.Signature.S.Cmp(sigS), "Signature S mismatch")
}

func TestDeserialize_KeyAuthorization_14Fields(t *testing.T) {
	keyAuthTuple := []interface{}{
		common.HexToAddress("0xabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd").Bytes(),
		[]byte{0x01, 0x02, 0x03},
	}

	serialized := encodeToHex(t, buildKeyAuthRLPList(keyAuthTuple, nil))

	tx, err := Deserialize(serialized)
	assert.NoError(t, err)

	assert.NotNil(t, tx.KeyAuthorization, "KeyAuthorization should be present")
	assert.Nil(t, tx.Signature, "Signature should be nil when only 14 fields with keyAuth")
}

func TestDeserialize_KeyAuthorization_InvalidFieldShapesRejected(t *testing.T) {
	t.Run("15_fields_signature_in_field_13_is_rejected", func(t *testing.T) {
		sigEnvelope, _, _ := makeSecp256k1Envelope()
		rlpList := append(buildKeyAuthRLPList(nil, sigEnvelope), []byte{0xab, 0xcd})

		serialized := encodeToHex(t, rlpList)
		_, err := Deserialize(serialized)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid field 13 type for 15-field transaction")
	})

	t.Run("15_fields_non_bytes_field_14_is_rejected", func(t *testing.T) {
		keyAuthTuple := []interface{}{
			common.HexToAddress("0xabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd").Bytes(),
			[]byte{0x01, 0x02, 0x03},
		}
		rlpList := buildKeyAuthRLPList(keyAuthTuple, nil)
		rlpList = append(rlpList, []interface{}{})

		serialized := encodeToHex(t, rlpList)
		_, err := Deserialize(serialized)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid field 14 type: expected signatureEnvelope bytes")
	})

	t.Run("14_fields_invalid_signature_envelope_is_rejected", func(t *testing.T) {
		rlpList := buildKeyAuthRLPList(nil, nil)
		rlpList = append(rlpList, big.NewInt(1).Bytes())

		serialized := encodeToHex(t, rlpList)
		_, err := Deserialize(serialized)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode signature envelope")
	})
}

func TestDeserialize_FieldCount_Rejected(t *testing.T) {
	tests := []struct {
		name       string
		fieldCount int
		wantErr    string
	}{
		{"12_fields_rejected", 12, "expected 13, 14, or 15 fields, got 12"},
		{"16_fields_rejected", 16, "expected 13, 14, or 15 fields, got 16"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rlpList := make([]interface{}, tt.fieldCount)
			for i := range rlpList {
				rlpList[i] = []byte{}
			}
			if tt.fieldCount > 4 {
				rlpList[4] = []interface{}{}
			}
			if tt.fieldCount > 5 {
				rlpList[5] = []interface{}{}
			}
			if tt.fieldCount > 12 {
				rlpList[12] = []interface{}{}
			}

			serialized := encodeToHex(t, rlpList)
			_, err := Deserialize(serialized)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestDeserialize_KeyAuthorization_Roundtrip(t *testing.T) {
	sigEnvelope, _, _ := makeSecp256k1Envelope()
	keyAuthTuple := []interface{}{
		common.HexToAddress("0xabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd").Bytes(),
		[]byte{0x01, 0x02, 0x03},
		big.NewInt(9999999).Bytes(),
	}

	original := encodeToHex(t, buildKeyAuthRLPList(keyAuthTuple, sigEnvelope))

	tx1, err := Deserialize(original)
	assert.NoError(t, err)

	serialized1, err := Serialize(tx1, nil)
	assert.NoError(t, err)

	tx2, err := Deserialize(serialized1)
	assert.NoError(t, err)

	assert.Equal(t, 0, tx1.ChainID.Cmp(tx2.ChainID), "ChainID mismatch after roundtrip")
	assert.Equal(t, tx1.Gas, tx2.Gas, "Gas mismatch after roundtrip")
	assert.NotNil(t, tx2.KeyAuthorization, "KeyAuthorization lost after roundtrip")
	assert.Equal(t, len(tx1.KeyAuthorization), len(tx2.KeyAuthorization), "KeyAuthorization tuple length mismatch")
	assert.NotNil(t, tx2.Signature, "Signature lost after roundtrip")
	assert.Equal(t, 0, tx1.Signature.Signature.R.Cmp(tx2.Signature.Signature.R), "Signature R mismatch")

	// Double roundtrip produces identical bytes
	serialized2, err := Serialize(tx2, nil)
	assert.NoError(t, err)
	assert.Equal(t, serialized1, serialized2, "Double roundtrip should produce identical bytes")
}

func TestSerialize_KeyAuthorization_FieldCount(t *testing.T) {
	baseTx := func() *Tx {
		return &Tx{
			ChainID:              big.NewInt(42424),
			MaxPriorityFeePerGas: big.NewInt(1000000),
			MaxFeePerGas:         big.NewInt(2000000),
			Gas:                  21000,
			Calls: []Call{
				{To: addrPtr(common.HexToAddress("0x1234567890123456789012345678901234567890")), Value: big.NewInt(0), Data: []byte{}},
			},
			AccessList: AccessList{},
			NonceKey:   big.NewInt(0),
			Nonce:      1,
			FeeToken:   common.HexToAddress("0x20c0000000000000000000000000000000000001"),
			Signature:  signer.NewSignatureEnvelope(big.NewInt(12345), big.NewInt(67890), 0),
		}
	}

	t.Run("without_key_authorization_produces_14_fields", func(t *testing.T) {
		tx := baseTx()
		serialized, err := Serialize(tx, nil)
		assert.NoError(t, err)
		deserialized, err := Deserialize(serialized)
		assert.NoError(t, err)
		assert.Nil(t, deserialized.KeyAuthorization)
		assert.NotNil(t, deserialized.Signature)
	})

	t.Run("with_key_authorization_produces_15_fields", func(t *testing.T) {
		tx := baseTx()
		tx.KeyAuthorization = []interface{}{
			common.HexToAddress("0xabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd").Bytes(),
			[]byte{0x01, 0x02, 0x03},
		}
		serialized, err := Serialize(tx, nil)
		assert.NoError(t, err)
		deserialized, err := Deserialize(serialized)
		assert.NoError(t, err)
		assert.NotNil(t, deserialized.KeyAuthorization)
		assert.NotNil(t, deserialized.Signature)
	})
}

func TestSerialize_KeyAuthorization_FeePayerFlow(t *testing.T) {
	senderSgn, err := signer.NewSigner("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	assert.NoError(t, err)
	feePayerSgn, err := signer.NewSigner("0xdd83cd66cd98801a07e0b7c1a5b02364b369e696da7c0ab444acffea5cca86fc")
	assert.NoError(t, err)

	tx := NewBuilder(big.NewInt(42424)).
		SetGas(21000).
		AddCall(common.HexToAddress("0x1234567890123456789012345678901234567890"), big.NewInt(0), []byte{}).
		Build()
	tx.KeyAuthorization = []interface{}{
		common.HexToAddress("0xabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd").Bytes(),
		[]byte{0x01, 0x02, 0x03},
	}

	err = SignTransaction(tx, senderSgn)
	assert.NoError(t, err)

	serialized, err := Serialize(tx, nil)
	assert.NoError(t, err)

	txServer, err := Deserialize(serialized)
	assert.NoError(t, err)
	assert.NotNil(t, txServer.KeyAuthorization)

	err = AddFeePayerSignature(txServer, feePayerSgn)
	assert.NoError(t, err)

	reSerialized, err := Serialize(txServer, nil)
	assert.NoError(t, err)

	txFinal, err := Deserialize(reSerialized)
	assert.NoError(t, err)
	assert.NotNil(t, txFinal.KeyAuthorization, "KeyAuthorization should survive full fee payer flow")
	assert.NotNil(t, txFinal.Signature, "Sender signature should be present")
	assert.NotNil(t, txFinal.FeePayerSignature, "Fee payer signature should be present")
}

// TestSerializeForFeePayerSigning_ZeroSender verifies that zero sender address is rejected.
func TestSerializeForFeePayerSigning_ZeroSender(t *testing.T) {
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
	}

	_, err := SerializeForFeePayerSigning(tx, common.Address{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "sender address is required")
}

// TestKeychainSignatureRoundtrip verifies keychain signatures can be serialized and deserialized.
// Per Tempo Transaction spec, keychain format is: 0x04 + user_address (20 bytes) + inner_sig (65 bytes) = 86 bytes
func TestKeychainSignatureRoundtrip(t *testing.T) {
	// Build a proper 86-byte keychain signature:
	// - Type prefix: 0x04
	// - User address: 20 bytes
	// - Inner signature (r || s || yParity): 65 bytes
	rawKeychainSig := make([]byte, 86)
	rawKeychainSig[0] = 0x04 // Type prefix
	// User address (bytes 1-20)
	copy(rawKeychainSig[1:21], common.HexToAddress("0xabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd").Bytes())
	// Inner signature R (bytes 21-52)
	copy(rawKeychainSig[21:53], common.Hex2Bytes("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"))
	// Inner signature S (bytes 53-84)
	copy(rawKeychainSig[53:85], common.Hex2Bytes("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"))
	// Inner signature yParity (byte 85)
	rawKeychainSig[85] = 0x01

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
		AccessList: AccessList{},
		NonceKey:   big.NewInt(0),
		Nonce:      1,
		Signature: &signer.SignatureEnvelope{
			Type: "keychain",
			Raw:  rawKeychainSig,
		},
	}

	serialized, err := Serialize(tx, nil)
	assert.NoError(t, err)

	deserialized, err := Deserialize(serialized)
	assert.NoError(t, err)

	assert.NotNil(t, deserialized.Signature)
	assert.Equal(t, "keychain", deserialized.Signature.Type)
	assert.Equal(t, rawKeychainSig, deserialized.Signature.Raw, "Keychain signature raw bytes should round-trip")
}
