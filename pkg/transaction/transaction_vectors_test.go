package transaction

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tempoxyz/tempo-go/pkg/signer"
)

// TestValidTransactionVectors tests a set of valid transaction configurations
// using test vectors.
func TestValidTransactionVectors(t *testing.T) {
	senderSigner, err := signer.NewSigner("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	require.NoError(t, err)
	feePayerSigner, err := signer.NewSigner("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d")
	require.NoError(t, err)

	addr1 := common.HexToAddress("0x70997970c51812dc3a010c7d01b50e0d17dc79c8")
	addr2 := common.HexToAddress("0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc")
	feeTokenAddr := common.HexToAddress("0x20c0000000000000000000000000000000000001")

	tests := []struct {
		name             string
		tx               *Tx
		signWithSender   bool
		signWithFeePayer bool
		shouldValidate   bool
		expectedSignType string
		// Expected serialized transaction hex string
		expectedSerialized string
		description        string
	}{
		// === BASIC TRANSACTIONS ===
		{
			name: "minimal_transaction",
			tx: &Tx{
				ChainID:              big.NewInt(1),
				MaxPriorityFeePerGas: big.NewInt(1000000000),
				MaxFeePerGas:         big.NewInt(2000000000),
				Gas:                  21000,
				Calls: []Call{
					{To: &addr1, Value: big.NewInt(0), Data: []byte{}},
				},
				NonceKey: big.NewInt(0),
				Nonce:    0,
			},
			signWithSender:     true,
			signWithFeePayer:   false,
			shouldValidate:     true,
			expectedSignType:   SignatureTypeSecp256k1,
			expectedSerialized: "0x76f87201843b9aca008477359400825208d8d79470997970c51812dc3a010c7d01b50e0d17dc79c88080c0808080808080c0b8415699d8feb5ace056f1c1e93c420f53942e7b9f31058cb2a2bb26550e5930ef1a55f6bdd3a27105268536dfe17f386d79f6c8b949698d105838455a20a857c33801",
			description:        "Minimal valid transaction with only required fields",
		},
		{
			name: "transaction_with_all_fields",
			tx: &Tx{
				ChainID:              big.NewInt(1337),
				MaxPriorityFeePerGas: big.NewInt(2000000000),
				MaxFeePerGas:         big.NewInt(3000000000),
				Gas:                  100000,
				Calls: []Call{
					{To: &addr1, Value: big.NewInt(1000000000000000000), Data: []byte{0xde, 0xad, 0xbe, 0xef}},
				},
				AccessList: AccessList{
					{
						Address: addr2,
						StorageKeys: []common.Hash{
							common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001"),
						},
					},
				},
				NonceKey:    big.NewInt(0),
				Nonce:       5,
				ValidBefore: 2000000000,
				ValidAfter:  1000000000,
				FeeToken:    feeTokenAddr,
			},
			signWithSender:   true,
			signWithFeePayer: false,
			shouldValidate:   true,
			expectedSignType: SignatureTypeSecp256k1,
			description:      "Transaction with all optional fields populated",
		},

		// === CALL VARIATIONS ===
		{
			name: "single_call_zero_value",
			tx: &Tx{
				ChainID:              big.NewInt(42424),
				MaxPriorityFeePerGas: big.NewInt(1000000000),
				MaxFeePerGas:         big.NewInt(2000000000),
				Gas:                  21000,
				Calls: []Call{
					{To: &addr1, Value: big.NewInt(0), Data: []byte{}},
				},
				NonceKey: big.NewInt(0),
				Nonce:    0,
			},
			signWithSender:   true,
			signWithFeePayer: false,
			shouldValidate:   true,
			expectedSignType: SignatureTypeSecp256k1,
			description:      "Single call with zero value and no data",
		},
		{
			name: "single_call_with_value",
			tx: &Tx{
				ChainID:              big.NewInt(42424),
				MaxPriorityFeePerGas: big.NewInt(1000000000),
				MaxFeePerGas:         big.NewInt(2000000000),
				Gas:                  21000,
				Calls: []Call{
					{To: &addr1, Value: new(big.Int).Mul(big.NewInt(5), big.NewInt(1e18)), Data: []byte{}},
				},
				NonceKey: big.NewInt(0),
				Nonce:    0,
			},
			signWithSender:   true,
			signWithFeePayer: false,
			shouldValidate:   true,
			expectedSignType: SignatureTypeSecp256k1,
			description:      "Single call with non-zero value (5 ETH)",
		},
		{
			name: "single_call_with_calldata",
			tx: &Tx{
				ChainID:              big.NewInt(42424),
				MaxPriorityFeePerGas: big.NewInt(1000000000),
				MaxFeePerGas:         big.NewInt(2000000000),
				Gas:                  50000,
				Calls: []Call{
					{
						To:    &addr1,
						Value: big.NewInt(0),
						// Simple calldata for a function call
						Data: []byte{0xa9, 0x05, 0x9c, 0xbb, 0x00, 0x00, 0x00, 0x00},
					},
				},
				NonceKey: big.NewInt(0),
				Nonce:    0,
			},
			signWithSender:   true,
			signWithFeePayer: false,
			shouldValidate:   true,
			expectedSignType: SignatureTypeSecp256k1,
			description:      "Single call with calldata",
		},
		{
			name: "multiple_calls_batch",
			tx: &Tx{
				ChainID:              big.NewInt(42424),
				MaxPriorityFeePerGas: big.NewInt(1000000000),
				MaxFeePerGas:         big.NewInt(2000000000),
				Gas:                  150000,
				Calls: []Call{
					{To: &addr1, Value: big.NewInt(1000000000), Data: []byte{}},
					{To: &addr2, Value: big.NewInt(2000000000), Data: []byte{0xaa, 0xbb}},
					{To: &addr1, Value: big.NewInt(0), Data: []byte{0xcc, 0xdd, 0xee}},
				},
				NonceKey: big.NewInt(0),
				Nonce:    0,
			},
			signWithSender:   true,
			signWithFeePayer: false,
			shouldValidate:   true,
			expectedSignType: SignatureTypeSecp256k1,
			description:      "Multiple calls in a batch (3 calls)",
		},
		// === NONCE KEY SCENARIOS ===
		{
			name: "protocol_nonce_key",
			tx: &Tx{
				ChainID:              big.NewInt(1),
				MaxPriorityFeePerGas: big.NewInt(1000000000),
				MaxFeePerGas:         big.NewInt(2000000000),
				Gas:                  21000,
				Calls: []Call{
					{To: &addr1, Value: big.NewInt(0), Data: []byte{}},
				},
				NonceKey: big.NewInt(0), // Protocol nonce
				Nonce:    0,
			},
			signWithSender:   true,
			signWithFeePayer: false,
			shouldValidate:   true,
			expectedSignType: SignatureTypeSecp256k1,
			description:      "Transaction using protocol nonce key (0)",
		},
		{
			name: "user_nonce_key_1",
			tx: &Tx{
				ChainID:              big.NewInt(1),
				MaxPriorityFeePerGas: big.NewInt(1000000000),
				MaxFeePerGas:         big.NewInt(2000000000),
				Gas:                  21000,
				Calls: []Call{
					{To: &addr1, Value: big.NewInt(0), Data: []byte{}},
				},
				NonceKey: big.NewInt(1), // User nonce key
				Nonce:    0,
			},
			signWithSender:   true,
			signWithFeePayer: false,
			shouldValidate:   true,
			expectedSignType: SignatureTypeSecp256k1,
			description:      "Transaction using user nonce key (1)",
		},
		{
			name: "user_nonce_key_large",
			tx: &Tx{
				ChainID:              big.NewInt(1),
				MaxPriorityFeePerGas: big.NewInt(1000000000),
				MaxFeePerGas:         big.NewInt(2000000000),
				Gas:                  21000,
				Calls: []Call{
					{To: &addr1, Value: big.NewInt(0), Data: []byte{}},
				},
				NonceKey: big.NewInt(99999),
				Nonce:    0,
			},
			signWithSender:   true,
			signWithFeePayer: false,
			shouldValidate:   true,
			expectedSignType: SignatureTypeSecp256k1,
			description:      "Transaction using large user nonce key",
		},
		// === GAS AND FEE CONFIGURATIONS ===
		{
			name: "standard_gas_21000",
			tx: &Tx{
				ChainID:              big.NewInt(1),
				MaxPriorityFeePerGas: big.NewInt(1000000000),
				MaxFeePerGas:         big.NewInt(2000000000),
				Gas:                  21000,
				Calls: []Call{
					{To: &addr1, Value: big.NewInt(0), Data: []byte{}},
				},
				NonceKey: big.NewInt(0),
				Nonce:    0,
			},
			signWithSender:   true,
			signWithFeePayer: false,
			shouldValidate:   true,
			expectedSignType: SignatureTypeSecp256k1,
			description:      "Standard gas limit (21000)",
		},
		{
			name: "high_gas_limit",
			tx: &Tx{
				ChainID:              big.NewInt(1),
				MaxPriorityFeePerGas: big.NewInt(1000000000),
				MaxFeePerGas:         big.NewInt(2000000000),
				Gas:                  10000000,
				Calls: []Call{
					{To: &addr1, Value: big.NewInt(0), Data: []byte{}},
				},
				NonceKey: big.NewInt(0),
				Nonce:    0,
			},
			signWithSender:   true,
			signWithFeePayer: false,
			shouldValidate:   true,
			expectedSignType: SignatureTypeSecp256k1,
			description:      "High gas limit for complex operations",
		},
		{
			name: "high_gas_prices",
			tx: &Tx{
				ChainID:              big.NewInt(1),
				MaxPriorityFeePerGas: new(big.Int).Mul(big.NewInt(100), big.NewInt(1e9)), // 100 gwei
				MaxFeePerGas:         new(big.Int).Mul(big.NewInt(200), big.NewInt(1e9)), // 200 gwei
				Gas:                  21000,
				Calls: []Call{
					{To: &addr1, Value: big.NewInt(0), Data: []byte{}},
				},
				NonceKey: big.NewInt(0),
				Nonce:    0,
			},
			signWithSender:   true,
			signWithFeePayer: false,
			shouldValidate:   true,
			expectedSignType: SignatureTypeSecp256k1,
			description:      "High gas prices (100/200 gwei)",
		},

		// === FEE TOKEN ===
		{
			name: "without_fee_token",
			tx: &Tx{
				ChainID:              big.NewInt(1),
				MaxPriorityFeePerGas: big.NewInt(1000000000),
				MaxFeePerGas:         big.NewInt(2000000000),
				Gas:                  21000,
				Calls: []Call{
					{To: &addr1, Value: big.NewInt(0), Data: []byte{}},
				},
				NonceKey: big.NewInt(0),
				Nonce:    0,
				FeeToken: common.Address{}, // No fee token
			},
			signWithSender:   true,
			signWithFeePayer: false,
			shouldValidate:   true,
			expectedSignType: SignatureTypeSecp256k1,
			description:      "Transaction without fee token (native token)",
		},
		{
			name: "with_fee_token",
			tx: &Tx{
				ChainID:              big.NewInt(1),
				MaxPriorityFeePerGas: big.NewInt(1000000000),
				MaxFeePerGas:         big.NewInt(2000000000),
				Gas:                  21000,
				Calls: []Call{
					{To: &addr1, Value: big.NewInt(0), Data: []byte{}},
				},
				NonceKey: big.NewInt(0),
				Nonce:    0,
				FeeToken: feeTokenAddr,
			},
			signWithSender:   true,
			signWithFeePayer: false,
			shouldValidate:   true,
			expectedSignType: SignatureTypeSecp256k1,
			description:      "Transaction with fee token preference",
		},

		// === FEE PAYER SPONSORSHIP ===
		{
			name: "self_paid_transaction",
			tx: &Tx{
				ChainID:              big.NewInt(1),
				MaxPriorityFeePerGas: big.NewInt(1000000000),
				MaxFeePerGas:         big.NewInt(2000000000),
				Gas:                  21000,
				Calls: []Call{
					{To: &addr1, Value: big.NewInt(0), Data: []byte{}},
				},
				NonceKey: big.NewInt(0),
				Nonce:    0,
			},
			signWithSender:   true,
			signWithFeePayer: false, // No fee payer
			shouldValidate:   true,
			expectedSignType: SignatureTypeSecp256k1,
			description:      "Self-paid transaction (no fee payer)",
		},
		{
			name: "sponsored_transaction",
			tx: &Tx{
				ChainID:              big.NewInt(1),
				MaxPriorityFeePerGas: big.NewInt(1000000000),
				MaxFeePerGas:         big.NewInt(2000000000),
				Gas:                  21000,
				Calls: []Call{
					{To: &addr1, Value: big.NewInt(0), Data: []byte{}},
				},
				NonceKey: big.NewInt(0),
				Nonce:    0,
			},
			signWithSender:     true,
			signWithFeePayer:   true, // With fee payer
			shouldValidate:     true,
			expectedSignType:   SignatureTypeSecp256k1,
			expectedSerialized: "0x76f8b601843b9aca008477359400825208d8d79470997970c51812dc3a010c7d01b50e0d17dc79c88080c08080808080f84380a0d86350bfb64659c00dcea2682a47dc8c119373b8d0af7ea465f60496508f131ca037a115d2bec8ee3d0af83df5873de151ce16fc7a26ed835143ccad962cab9132c0b8415699d8feb5ace056f1c1e93c420f53942e7b9f31058cb2a2bb26550e5930ef1a55f6bdd3a27105268536dfe17f386d79f6c8b949698d105838455a20a857c33801",
			description:        "Sponsored transaction with fee payer",
		},
		{
			name: "sponsored_with_fee_token",
			tx: &Tx{
				ChainID:              big.NewInt(1),
				MaxPriorityFeePerGas: big.NewInt(1000000000),
				MaxFeePerGas:         big.NewInt(2000000000),
				Gas:                  21000,
				Calls: []Call{
					{To: &addr1, Value: big.NewInt(0), Data: []byte{}},
				},
				NonceKey: big.NewInt(0),
				Nonce:    0,
				FeeToken: feeTokenAddr,
			},
			signWithSender:   true,
			signWithFeePayer: true, // With fee payer
			shouldValidate:   true,
			expectedSignType: SignatureTypeSecp256k1,
			description:      "Sponsored transaction with fee token preference",
		},

		// === VALIDITY WINDOWS ===
		{
			name: "no_validity_window",
			tx: &Tx{
				ChainID:              big.NewInt(1),
				MaxPriorityFeePerGas: big.NewInt(1000000000),
				MaxFeePerGas:         big.NewInt(2000000000),
				Gas:                  21000,
				Calls: []Call{
					{To: &addr1, Value: big.NewInt(0), Data: []byte{}},
				},
				NonceKey:    big.NewInt(0),
				Nonce:       0,
				ValidBefore: 0, // No expiration
				ValidAfter:  0, // No delay
			},
			signWithSender:   true,
			signWithFeePayer: false,
			shouldValidate:   true,
			expectedSignType: SignatureTypeSecp256k1,
			description:      "No validity window (always valid)",
		},
		{
			name: "with_valid_before",
			tx: &Tx{
				ChainID:              big.NewInt(1),
				MaxPriorityFeePerGas: big.NewInt(1000000000),
				MaxFeePerGas:         big.NewInt(2000000000),
				Gas:                  21000,
				Calls: []Call{
					{To: &addr1, Value: big.NewInt(0), Data: []byte{}},
				},
				NonceKey:    big.NewInt(0),
				Nonce:       0,
				ValidBefore: 2000000000, // Unix timestamp
				ValidAfter:  0,
			},
			signWithSender:   true,
			signWithFeePayer: false,
			shouldValidate:   true,
			expectedSignType: SignatureTypeSecp256k1,
			description:      "Transaction with expiration time (validBefore)",
		},
		{
			name: "with_valid_after",
			tx: &Tx{
				ChainID:              big.NewInt(1),
				MaxPriorityFeePerGas: big.NewInt(1000000000),
				MaxFeePerGas:         big.NewInt(2000000000),
				Gas:                  21000,
				Calls: []Call{
					{To: &addr1, Value: big.NewInt(0), Data: []byte{}},
				},
				NonceKey:    big.NewInt(0),
				Nonce:       0,
				ValidBefore: 0,
				ValidAfter:  1000000000, // Unix timestamp
			},
			signWithSender:   true,
			signWithFeePayer: false,
			shouldValidate:   true,
			expectedSignType: SignatureTypeSecp256k1,
			description:      "Transaction with activation time (validAfter)",
		},
		{
			name: "with_validity_window",
			tx: &Tx{
				ChainID:              big.NewInt(1),
				MaxPriorityFeePerGas: big.NewInt(1000000000),
				MaxFeePerGas:         big.NewInt(2000000000),
				Gas:                  21000,
				Calls: []Call{
					{To: &addr1, Value: big.NewInt(0), Data: []byte{}},
				},
				NonceKey:    big.NewInt(0),
				Nonce:       0,
				ValidBefore: 2000000000, // Unix timestamp
				ValidAfter:  1000000000, // Unix timestamp
			},
			signWithSender:   true,
			signWithFeePayer: false,
			shouldValidate:   true,
			expectedSignType: SignatureTypeSecp256k1,
			description:      "Transaction with validity window (validAfter < validBefore)",
		},

		// === DIFFERENT CHAIN IDS ===
		{
			name: "local_chain_id",
			tx: &Tx{
				ChainID:              big.NewInt(1337),
				MaxPriorityFeePerGas: big.NewInt(1000000000),
				MaxFeePerGas:         big.NewInt(2000000000),
				Gas:                  21000,
				Calls: []Call{
					{To: &addr1, Value: big.NewInt(0), Data: []byte{}},
				},
				NonceKey: big.NewInt(0),
				Nonce:    0,
			},
			signWithSender:   true,
			signWithFeePayer: false,
			shouldValidate:   true,
			expectedSignType: SignatureTypeSecp256k1,
			description:      "Local testnet chain ID (1337)",
		},
		{
			name: "custom_chain_id",
			tx: &Tx{
				ChainID:              big.NewInt(42424),
				MaxPriorityFeePerGas: big.NewInt(1000000000),
				MaxFeePerGas:         big.NewInt(2000000000),
				Gas:                  21000,
				Calls: []Call{
					{To: &addr1, Value: big.NewInt(0), Data: []byte{}},
				},
				NonceKey: big.NewInt(0),
				Nonce:    0,
			},
			signWithSender:   true,
			signWithFeePayer: false,
			shouldValidate:   true,
			expectedSignType: SignatureTypeSecp256k1,
			description:      "Custom chain ID (42424)",
		},
		// Add new tests here....
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.shouldValidate {
				err := tt.tx.Validate()
				assert.NoError(t, err, "Transaction should be valid: %s", tt.description)
			}

			if tt.signWithSender {
				err = SignTransaction(tt.tx, senderSigner)
				require.NoError(t, err, "Failed to sign transaction: %s", tt.description)
				assert.NotNil(t, tt.tx.Signature, "Signature should be present")
				assert.Equal(t, tt.expectedSignType, tt.tx.Signature.Type, "Signature type mismatch")
			}

			if tt.signWithFeePayer {
				err = AddFeePayerSignature(tt.tx, feePayerSigner)
				require.NoError(t, err, "Failed to add fee payer signature: %s", tt.description)
				assert.NotNil(t, tt.tx.FeePayerSignature, "Fee payer signature should be present")
			}

			serialized, err := Serialize(tt.tx, nil)
			require.NoError(t, err, "Failed to serialize transaction: %s", tt.description)
			assert.Equal(t, "0x76", serialized[:4], "Serialized transaction should start with 0x76")

			deserialized, err := Deserialize(serialized)
			require.NoError(t, err, "Failed to deserialize transaction: %s", tt.description)
			assert.NotNil(t, deserialized, "Deserialized transaction should not be nil")

			assert.Equal(t, tt.tx.ChainID, deserialized.ChainID, "ChainID mismatch after roundtrip")
			assert.Equal(t, tt.tx.Gas, deserialized.Gas, "Gas mismatch after roundtrip")
			assert.Equal(t, tt.tx.Nonce, deserialized.Nonce, "Nonce mismatch after roundtrip")
			assert.Equal(t, len(tt.tx.Calls), len(deserialized.Calls), "Calls count mismatch after roundtrip")

			if tt.signWithSender {
				assert.NotNil(t, deserialized.Signature, "Signature lost after roundtrip")
				recoveredSender, err := VerifySignature(deserialized)
				require.NoError(t, err, "Failed to verify signature: %s", tt.description)
				assert.Equal(t, senderSigner.Address(), recoveredSender, "Sender address mismatch after signature verification")
			}

			if tt.signWithFeePayer {
				assert.NotNil(t, deserialized.FeePayerSignature, "Fee payer signature lost after roundtrip")
				recoveredFeePayer, err := VerifyFeePayerSignature(deserialized, senderSigner.Address())
				require.NoError(t, err, "Failed to verify fee payer signature: %s", tt.description)
				assert.Equal(t, feePayerSigner.Address(), recoveredFeePayer, "Fee payer address mismatch after signature verification")
			}

			if tt.signWithSender {
				hash1, err := deserialized.Hash()
				require.NoError(t, err, "Failed to compute transaction hash")
				hash2, err := deserialized.Hash()
				require.NoError(t, err, "Failed to compute transaction hash (second time)")
				assert.Equal(t, hash1, hash2, "Transaction hash should be deterministic")
			}

			if tt.expectedSerialized != "" {
				assert.Equal(t, tt.expectedSerialized, serialized,
					"Serialized transaction mismatch for %s.\nIf this is intentional, update the expectedSerialized field in the test.", tt.name)
			}
		})
	}
}

// TestSerializationFormats tests different serialization formats
func TestSerializationFormats(t *testing.T) {
	senderSigner, err := signer.NewSigner("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	require.NoError(t, err)
	feePayerSigner, err := signer.NewSigner("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d")
	require.NoError(t, err)

	addr1 := common.HexToAddress("0x70997970c51812dc3a010c7d01b50e0d17dc79c8")

	tx := &Tx{
		ChainID:              big.NewInt(1),
		MaxPriorityFeePerGas: big.NewInt(1000000000),
		MaxFeePerGas:         big.NewInt(2000000000),
		Gas:                  21000,
		Calls: []Call{
			{To: &addr1, Value: big.NewInt(0), Data: []byte{}},
		},
		NonceKey: big.NewInt(0),
		Nonce:    0,
	}

	tests := []struct {
		name           string
		opts           *SerializeOptions
		expectedPrefix string
		description    string
	}{
		{
			name:           "normal_format",
			opts:           &SerializeOptions{Format: FormatNormal},
			expectedPrefix: "0x76",
			description:    "Normal sender format (0x76 prefix)",
		},
		{
			name: "fee_payer_format",
			opts: &SerializeOptions{
				Format: FormatFeePayer,
				Sender: senderSigner.Address(),
			},
			expectedPrefix: "0x78",
			description:    "Fee payer signing format (0x78 prefix)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := SignTransaction(tx, senderSigner)
			require.NoError(t, err)

			if tt.opts.Format == FormatFeePayer {
				err = AddFeePayerSignature(tx, feePayerSigner)
				require.NoError(t, err)
			}

			serialized, err := Serialize(tx, tt.opts)
			require.NoError(t, err, "Failed to serialize with format: %s", tt.description)
			assert.Equal(t, tt.expectedPrefix, serialized[:4], "Prefix mismatch: %s", tt.description)
		})
	}
}
