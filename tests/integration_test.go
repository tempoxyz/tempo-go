package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tempoxyz/tempo-go/pkg/client"
	"github.com/tempoxyz/tempo-go/pkg/keychain"
	"github.com/tempoxyz/tempo-go/pkg/signer"
	"github.com/tempoxyz/tempo-go/pkg/transaction"
)

// Precompile and token addresses
var (
	nativeFeeToken  = common.HexToAddress("0x20c0000000000000000000000000000000000000")
	alphaUSD        = common.HexToAddress("0x20C0000000000000000000000000000000000001")
	betaUSD         = common.HexToAddress("0x20C0000000000000000000000000000000000002")
	thetaUSD        = common.HexToAddress("0x20C0000000000000000000000000000000000003")
	feeController   = common.HexToAddress("0xfeec000000000000000000000000000000000000")
	accountKeychain = common.HexToAddress("0xAAAAAAAA00000000000000000000000000000000")
	dex             = common.HexToAddress("0xdec0000000000000000000000000000000000000")
	counterContract = common.HexToAddress("0x86A2EE8FAf9A840F7a2c64CA3d51209F9A02081D")
	lpRecipient     = common.HexToAddress("0x6c4143BEd3A13cf9E5E43d45C60aD816FC091d0c")
)

// Function selectors
var (
	incrementSelector    = mustDecodeHex("d09de08a")
	mintSelector         = mustDecodeHex("f1aa8cb8")
	setUserTokenSelector = mustDecodeHex("e7897444")
	authorizeKeySelector = mustDecodeHex("54063a55")
)

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

var rpcURL string

func init() {
	rpcURL = os.Getenv("TEMPO_RPC_URL")
	if rpcURL == "" {
		panic("TEMPO_RPC_URL environment variable must be set to run integration tests. Example: export TEMPO_RPC_URL=https://rpc.testnet.tempo.xyz")
	}
}

// testContext encapsulates common test dependencies and helpers
type testContext struct {
	t        *testing.T
	ctx      context.Context
	client   *client.Client
	chainID  int64
	gasPrice *big.Int
}

// newTestContext creates a new test context with RPC client, chain ID, and gas price
func newTestContext(t *testing.T) *testContext {
	t.Helper()
	ctx := context.Background()
	rpcClient := client.New(rpcURL)

	id, err := rpcClient.GetChainID(ctx)
	require.NoError(t, err)

	gasPrice := fetchGasPrice(t, rpcClient)

	return &testContext{
		t:        t,
		ctx:      ctx,
		client:   rpcClient,
		chainID:  int64(id),
		gasPrice: gasPrice,
	}
}

// fetchGasPrice gets the current gas price with a 50% buffer
func fetchGasPrice(t *testing.T, rpcClient *client.Client) *big.Int {
	t.Helper()
	ctx := context.Background()
	resp, err := rpcClient.SendRequest(ctx, "eth_gasPrice")
	if err != nil || resp.Error != nil {
		return big.NewInt(50000000000) // 50 gwei fallback
	}
	gasPriceHex, ok := resp.Result.(string)
	if !ok {
		return big.NewInt(50000000000)
	}
	gasPrice := new(big.Int)
	gasPrice.SetString(strings.TrimPrefix(gasPriceHex, "0x"), 16)
	gasPrice.Mul(gasPrice, big.NewInt(3))
	gasPrice.Div(gasPrice, big.NewInt(2))
	return gasPrice
}

// waitForBalance polls until the address has a non-zero balance
func (tc *testContext) waitForBalance(address common.Address) {
	tc.t.Helper()
	for i := 0; i < 60; i++ {
		resp, err := tc.client.SendRequest(tc.ctx, "eth_getBalance", address.Hex(), "latest")
		if err == nil && resp.Error == nil {
			if balanceHex, ok := resp.Result.(string); ok {
				balance := new(big.Int)
				balance.SetString(strings.TrimPrefix(balanceHex, "0x"), 16)
				if balance.Sign() > 0 {
					tc.t.Logf("Address %s has balance %s", address.Hex(), balance.String())
					return
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	tc.t.Fatalf("Failed to get balance for %s after 30s", address.Hex())
}

// fundAddress funds an address and waits for tx receipts and balance confirmation
func (tc *testContext) fundAddress(address common.Address) {
	tc.t.Helper()
	var txHashes []string
	for i := 0; i < 100; i++ {
		resp, err := tc.client.SendRequest(tc.ctx, "tempo_fundAddress", address.Hex())
		if err == nil && resp.Error == nil {
			if result, ok := resp.Result.([]interface{}); ok && len(result) > 0 {
				tc.t.Logf("Funded address %s", address.Hex())
				for _, h := range result {
					if hash, ok := h.(string); ok {
						txHashes = append(txHashes, hash)
					}
				}
				break
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	// Wait for all funding tx receipts to ensure state is confirmed
	for _, txHash := range txHashes {
		tc.waitForReceipt(txHash)
	}
	tc.waitForBalance(address)
}

// createAndFundSigner creates a new signer and funds it
func (tc *testContext) createAndFundSigner() *signer.Signer {
	tc.t.Helper()
	privateKey, err := crypto.GenerateKey()
	require.NoError(tc.t, err)
	s := signer.NewSignerFromKey(privateKey)
	tc.fundAddress(s.Address())
	return s
}

// getNonce fetches the current nonce for an address
func (tc *testContext) getNonce(address common.Address) uint64 {
	tc.t.Helper()
	nonce, err := tc.client.GetTransactionCount(tc.ctx, address.Hex())
	require.NoError(tc.t, err)
	return nonce
}

// sendTx serializes, sends a transaction and waits for receipt
func (tc *testContext) sendTx(tx *transaction.Tx) (map[string]interface{}, string) {
	tc.t.Helper()
	serialized, err := transaction.Serialize(tx, nil)
	require.NoError(tc.t, err)

	txHash, err := tc.client.SendRawTransaction(tc.ctx, serialized)
	require.NoError(tc.t, err)
	tc.t.Logf("Transaction hash: %s", txHash)

	receipt := tc.waitForReceipt(txHash)
	return receipt, txHash
}

// sendTxExpectSuccess sends a tx and asserts it succeeds
func (tc *testContext) sendTxExpectSuccess(tx *transaction.Tx, msg string) map[string]interface{} {
	tc.t.Helper()
	receipt, _ := tc.sendTx(tx)
	require.NotNil(tc.t, receipt, "Failed to get receipt")
	status, _ := receipt["status"].(string)
	require.Equal(tc.t, "0x1", status, msg)
	tc.formatReceipt(receipt)
	return receipt
}

// waitForReceipt waits for a transaction receipt
func (tc *testContext) waitForReceipt(txHash string) map[string]interface{} {
	tc.t.Helper()
	for i := 0; i < 15; i++ {
		time.Sleep(2 * time.Second)
		resp, err := tc.client.SendRequest(tc.ctx, "eth_getTransactionReceipt", txHash)
		if err == nil && resp.Result != nil {
			if receipt, ok := resp.Result.(map[string]interface{}); ok {
				return receipt
			}
		}
	}
	tc.t.Logf("Warning: Receipt not available after 30 seconds for tx %s", txHash)
	return nil
}

// formatReceipt logs a formatted transaction receipt
func (tc *testContext) formatReceipt(receipt map[string]interface{}) {
	tc.t.Helper()
	if receipt == nil {
		tc.t.Logf("Receipt not available")
		return
	}

	status := "false"
	if s, ok := receipt["status"].(string); ok && s == "0x1" {
		status = "true"
	}

	txType := "unknown"
	if typeVal, ok := receipt["type"].(string); ok {
		switch typeVal {
		case "0x76":
			txType = "Tempo (0x76)"
		case "0x2":
			txType = "EIP-1559"
		case "0x0":
			txType = "Legacy"
		default:
			txType = typeVal
		}
	}

	tc.t.Logf("\n"+
		"status               %s\n"+
		"transactionHash      %s\n"+
		"type                 %s\n"+
		"from                 %v\n"+
		"to                   %v\n"+
		"feePayer             %v\n"+
		"feeToken             %v\n"+
		"gasUsed              %v\n"+
		"effectiveGasPrice    %v",
		status,
		receipt["transactionHash"],
		txType,
		receipt["from"],
		receipt["to"],
		receipt["feePayer"],
		receipt["feeToken"],
		receipt["gasUsed"],
		receipt["effectiveGasPrice"],
	)
}

// newTxBuilder creates a transaction builder with common defaults
func (tc *testContext) newTxBuilder() *transaction.Builder {
	return transaction.NewBuilder(big.NewInt(tc.chainID)).
		SetMaxFeePerGas(tc.gasPrice).
		SetMaxPriorityFeePerGas(tc.gasPrice)
}

// Encoding helpers
func encodeCalldata(selector []byte, args ...[]byte) []byte {
	result := make([]byte, len(selector))
	copy(result, selector)
	for _, arg := range args {
		result = append(result, arg...)
	}
	return result
}

func padLeft32(b []byte) []byte {
	if len(b) >= 32 {
		return b[:32]
	}
	result := make([]byte, 32)
	copy(result[32-len(b):], b)
	return result
}

func addressToBytes32(addr common.Address) []byte {
	return padLeft32(addr.Bytes())
}

func uint256ToBytes32(n *big.Int) []byte {
	return padLeft32(n.Bytes())
}

// TestIntegration_NodeConnection tests basic node connectivity
func TestIntegration_NodeConnection(t *testing.T) {
	tc := newTestContext(t)

	t.Run("GetBlockNumber", func(t *testing.T) {
		blockNum, err := tc.client.GetBlockNumber(tc.ctx)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, blockNum, uint64(0))
		t.Logf("Current block number: %d", blockNum)
	})

	t.Run("GetChainID", func(t *testing.T) {
		chainID, err := tc.client.GetChainID(tc.ctx)
		require.NoError(t, err)
		assert.Greater(t, chainID, uint64(0))
		t.Logf("Chain ID: %d", chainID)
	})

	t.Run("ClientVersion", func(t *testing.T) {
		resp, err := tc.client.SendRequest(tc.ctx, "web3_clientVersion")
		require.NoError(t, err)
		require.NoError(t, resp.CheckError())
		version, ok := resp.Result.(string)
		require.True(t, ok)
		assert.NotEmpty(t, version)
		t.Logf("Client version: %s", version)
	})
}

// TestIntegration_SimpleTransaction tests creating, signing, and sending a simple transaction
func TestIntegration_SimpleTransaction(t *testing.T) {
	tc := newTestContext(t)
	sender := tc.createAndFundSigner()
	t.Logf("Sender address: %s", sender.Address().Hex())

	tx := tc.newTxBuilder().
		SetNonce(tc.getNonce(sender.Address())).
		SetGas(300000).
		AddCall(counterContract, big.NewInt(0), incrementSelector).
		Build()

	err := transaction.SignTransaction(tx, sender)
	require.NoError(t, err)

	tc.sendTxExpectSuccess(tx, "Transaction failed")
}

// TestIntegration_FeeTokenLiquidity tests adding fee token liquidity
func TestIntegration_FeeTokenLiquidity(t *testing.T) {
	tc := newTestContext(t)
	sender := tc.createAndFundSigner()

	feeTokens := []struct {
		name  string
		token common.Address
	}{
		{"AlphaUSD", alphaUSD},
		{"BetaUSD", betaUSD},
		{"ThetaUSD", thetaUSD},
	}

	for _, ft := range feeTokens {
		t.Run(ft.name, func(t *testing.T) {
			calldata := encodeCalldata(
				mintSelector,
				addressToBytes32(ft.token),
				addressToBytes32(nativeFeeToken),
				uint256ToBytes32(big.NewInt(1000000000)),
				addressToBytes32(lpRecipient),
			)

			tx := tc.newTxBuilder().
				SetNonce(tc.getNonce(sender.Address())).
				SetGas(500000).
				AddCall(feeController, big.NewInt(0), calldata).
				Build()

			err := transaction.SignTransaction(tx, sender)
			require.NoError(t, err)

			tc.sendTxExpectSuccess(tx, "Transaction failed")
		})
	}
}

// TestIntegration_SendWithFeeToken tests sending transactions with custom fee tokens
func TestIntegration_SendWithFeeToken(t *testing.T) {
	tc := newTestContext(t)
	sender := tc.createAndFundSigner()

	feeTokens := []struct {
		name  string
		token common.Address
	}{
		{"BetaUSD", betaUSD},
		{"ThetaUSD", thetaUSD},
	}

	for _, ft := range feeTokens {
		t.Run(ft.name, func(t *testing.T) {
			tx := tc.newTxBuilder().
				SetNonce(tc.getNonce(sender.Address())).
				SetGas(300000).
				SetFeeToken(ft.token).
				AddCall(counterContract, big.NewInt(0), incrementSelector).
				Build()

			err := transaction.SignTransaction(tx, sender)
			require.NoError(t, err)

			tc.sendTxExpectSuccess(tx, "Transaction failed")
		})
	}
}

// TestIntegration_2DNonces tests 2D nonce system (nonce_key)
func TestIntegration_2DNonces(t *testing.T) {
	tc := newTestContext(t)
	sender := tc.createAndFundSigner()

	nonceKeys := []int64{1, 2, 3}

	for _, key := range nonceKeys {
		t.Run(fmt.Sprintf("NonceKey_%d", key), func(t *testing.T) {
			tx := tc.newTxBuilder().
				SetNonce(0).
				SetNonceKey(big.NewInt(key)).
				SetGas(300000).
				AddCall(counterContract, big.NewInt(0), incrementSelector).
				Build()

			err := transaction.SignTransaction(tx, sender)
			require.NoError(t, err)

			tc.sendTxExpectSuccess(tx, "Transaction failed")
		})
	}
}

// TestIntegration_ExpiringNonces tests expiring nonces (valid_before, valid_after)
func TestIntegration_ExpiringNonces(t *testing.T) {
	tc := newTestContext(t)
	sender := tc.createAndFundSigner()

	t.Run("ValidBefore", func(t *testing.T) {
		validBefore := uint64(time.Now().Unix() + 25)

		tx := tc.newTxBuilder().
			SetNonce(0).
			SetNonceKey(big.NewInt(100)).
			SetValidBefore(validBefore).
			SetGas(300000).
			AddCall(counterContract, big.NewInt(0), incrementSelector).
			Build()

		err := transaction.SignTransaction(tx, sender)
		require.NoError(t, err)

		tc.sendTxExpectSuccess(tx, "Transaction failed")
	})

	t.Run("ValidAfterAndBefore", func(t *testing.T) {
		now := time.Now().Unix()
		validAfter := uint64(now - 1)
		validBefore := uint64(now + 25)

		tx := tc.newTxBuilder().
			SetNonce(0).
			SetNonceKey(big.NewInt(101)).
			SetValidAfter(validAfter).
			SetValidBefore(validBefore).
			SetGas(300000).
			AddCall(counterContract, big.NewInt(0), incrementSelector).
			Build()

		err := transaction.SignTransaction(tx, sender)
		require.NoError(t, err)

		tc.sendTxExpectSuccess(tx, "Transaction failed")
	})
}

// TestIntegration_SponsoredTransaction tests sponsored (gasless) transactions
func TestIntegration_SponsoredTransaction(t *testing.T) {
	tc := newTestContext(t)
	sender := tc.createAndFundSigner()
	sponsor := tc.createAndFundSigner()

	t.Logf("Sender address: %s", sender.Address().Hex())
	t.Logf("Sponsor address: %s", sponsor.Address().Hex())

	tx := tc.newTxBuilder().
		SetNonce(0).
		SetNonceKey(big.NewInt(200)).
		SetGas(300000).
		AddCall(counterContract, big.NewInt(0), incrementSelector).
		Build()

	tx.AwaitingFeePayer = true

	err := transaction.SignTransaction(tx, sender)
	require.NoError(t, err)

	err = transaction.AddFeePayerSignature(tx, sponsor)
	require.NoError(t, err)

	recoveredSender, recoveredSponsor, err := transaction.VerifyDualSignatures(tx)
	require.NoError(t, err)
	assert.Equal(t, sender.Address(), recoveredSender)
	assert.Equal(t, sponsor.Address(), recoveredSponsor)

	receipt := tc.sendTxExpectSuccess(tx, "Sponsored transaction failed")

	feePayer, _ := receipt["feePayer"].(string)
	assert.True(t, strings.EqualFold(feePayer, sponsor.Address().Hex()),
		"Expected feePayer %s, got %s", sponsor.Address().Hex(), feePayer)
}

// TestIntegration_AccessKeys tests access key (keychain) signing
func TestIntegration_AccessKeys(t *testing.T) {
	tc := newTestContext(t)

	rootAccount := tc.createAndFundSigner()
	accessKeyPriv, err := crypto.GenerateKey()
	require.NoError(t, err)
	accessKey := signer.NewSignerFromKey(accessKeyPriv)

	t.Logf("Root account: %s", rootAccount.Address().Hex())
	t.Logf("Access key: %s", accessKey.Address().Hex())

	t.Run("AuthorizeAccessKey", func(t *testing.T) {
		calldata := encodeCalldata(
			authorizeKeySelector,
			addressToBytes32(accessKey.Address()),
			padLeft32([]byte{0}),
			uint256ToBytes32(big.NewInt(1893456000)),
			padLeft32([]byte{0}),
			uint256ToBytes32(big.NewInt(0xa0)),
			uint256ToBytes32(big.NewInt(0)),
		)

		eip1559Tx := types.NewTx(&types.DynamicFeeTx{
			ChainID:   big.NewInt(tc.chainID),
			Nonce:     tc.getNonce(rootAccount.Address()),
			GasTipCap: tc.gasPrice,
			GasFeeCap: tc.gasPrice,
			Gas:       600000,
			To:        &accountKeychain,
			Value:     big.NewInt(0),
			Data:      calldata,
		})

		signedTx, err := types.SignTx(eip1559Tx, types.NewLondonSigner(big.NewInt(tc.chainID)), rootAccount.PrivateKey())
		require.NoError(t, err)

		txBytes, err := signedTx.MarshalBinary()
		require.NoError(t, err)

		txHash, err := tc.client.SendRawTransaction(tc.ctx, "0x"+hex.EncodeToString(txBytes))
		require.NoError(t, err)
		t.Logf("Authorize access key tx hash: %s", txHash)

		receipt := tc.waitForReceipt(txHash)
		require.NotNil(t, receipt, "Failed to get authorization receipt")
		status, _ := receipt["status"].(string)
		require.Equal(t, "0x1", status, "Authorization tx failed")
		tc.formatReceipt(receipt)
	})

	time.Sleep(3 * time.Second)

	t.Run("SignWithAccessKey", func(t *testing.T) {
		tx := tc.newTxBuilder().
			SetNonce(0).
			SetNonceKey(big.NewInt(300)).
			SetGas(500000).
			AddCall(counterContract, big.NewInt(0), incrementSelector).
			Build()

		err := keychain.SignWithAccessKey(tx, accessKey, rootAccount.Address())
		require.NoError(t, err)

		recoveredAccessKey, recoveredRoot, err := keychain.VerifyAccessKeySignature(tx)
		require.NoError(t, err)
		assert.Equal(t, accessKey.Address(), recoveredAccessKey)
		assert.Equal(t, rootAccount.Address(), recoveredRoot)

		tc.sendTxExpectSuccess(tx, "Access key transaction failed")
	})
}

// TestIntegration_BatchTransactions tests transactions with multiple calls
func TestIntegration_BatchTransactions(t *testing.T) {
	tc := newTestContext(t)
	sender := tc.createAndFundSigner()

	t.Run("TwoCalls", func(t *testing.T) {
		tx := tc.newTxBuilder().
			SetNonce(tc.getNonce(sender.Address())).
			SetGas(300000).
			AddCall(counterContract, big.NewInt(0), incrementSelector).
			AddCall(counterContract, big.NewInt(0), incrementSelector).
			Build()

		err := transaction.SignTransaction(tx, sender)
		require.NoError(t, err)

		tc.sendTxExpectSuccess(tx, "Batch transaction failed")
	})

	t.Run("ThreeCalls", func(t *testing.T) {
		tx := tc.newTxBuilder().
			SetNonce(tc.getNonce(sender.Address())).
			SetGas(300000).
			AddCall(counterContract, big.NewInt(0), incrementSelector).
			AddCall(counterContract, big.NewInt(0), incrementSelector).
			AddCall(counterContract, big.NewInt(0), incrementSelector).
			Build()

		err := transaction.SignTransaction(tx, sender)
		require.NoError(t, err)

		tc.sendTxExpectSuccess(tx, "Batch transaction failed")
	})
}

// TestIntegration_SetUserFeeToken tests setting user's default fee token
func TestIntegration_SetUserFeeToken(t *testing.T) {
	tc := newTestContext(t)
	sender := tc.createAndFundSigner()

	t.Run("SetToBetaUSD", func(t *testing.T) {
		calldata := encodeCalldata(setUserTokenSelector, addressToBytes32(betaUSD))

		tx := tc.newTxBuilder().
			SetNonce(tc.getNonce(sender.Address())).
			SetGas(600000).
			AddCall(feeController, big.NewInt(0), calldata).
			Build()

		err := transaction.SignTransaction(tx, sender)
		require.NoError(t, err)

		tc.sendTxExpectSuccess(tx, "SetUserFeeToken failed")
	})

	t.Run("ResetToNative", func(t *testing.T) {
		calldata := encodeCalldata(setUserTokenSelector, addressToBytes32(nativeFeeToken))

		tx := tc.newTxBuilder().
			SetNonce(tc.getNonce(sender.Address())).
			SetGas(600000).
			AddCall(feeController, big.NewInt(0), calldata).
			Build()

		err := transaction.SignTransaction(tx, sender)
		require.NoError(t, err)

		tc.sendTxExpectSuccess(tx, "ResetUserFeeToken failed")
	})
}

// TestIntegration_DEXOperations tests DEX operations (skipped - require liquidity setup)
func TestIntegration_DEXOperations(t *testing.T) {
	t.Skip("DEX operations require liquidity setup - works with full tempo-check.sh flow")
}

// TestIntegration_BuilderValidation tests the BuildAndValidate method
func TestIntegration_BuilderValidation(t *testing.T) {
	tc := newTestContext(t)
	recipient := common.HexToAddress("0x1234567890123456789012345678901234567890")

	tx, err := transaction.NewBuilder(big.NewInt(tc.chainID)).
		SetGas(300000).
		AddCall(recipient, big.NewInt(0), []byte{}).
		BuildAndValidate()

	require.NoError(t, err)
	assert.NotNil(t, tx)

	_, err = transaction.NewBuilder(big.NewInt(tc.chainID)).
		AddCall(recipient, big.NewInt(0), []byte{}).
		BuildAndValidate()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "gas must be greater than 0")
}

// TestIntegration_RoundTrip tests full serialization round-trip
func TestIntegration_RoundTrip(t *testing.T) {
	tc := newTestContext(t)

	senderPriv, err := crypto.GenerateKey()
	require.NoError(t, err)
	sender := signer.NewSignerFromKey(senderPriv)

	recipient := common.HexToAddress("0x1234567890123456789012345678901234567890")

	originalTx := transaction.NewBuilder(big.NewInt(tc.chainID)).
		SetGas(300000).
		SetMaxFeePerGas(big.NewInt(10000000000)).
		SetMaxPriorityFeePerGas(big.NewInt(10000000000)).
		SetNonce(42).
		AddCall(recipient, big.NewInt(1000), []byte{0xaa, 0xbb}).
		Build()

	err = transaction.SignTransaction(originalTx, sender)
	require.NoError(t, err)

	serialized, err := transaction.Serialize(originalTx, nil)
	require.NoError(t, err)

	deserializedTx, err := transaction.Deserialize(serialized)
	require.NoError(t, err)

	assert.Equal(t, originalTx.ChainID.Int64(), deserializedTx.ChainID.Int64())
	assert.Equal(t, originalTx.Gas, deserializedTx.Gas)
	assert.Equal(t, originalTx.Nonce, deserializedTx.Nonce)
	assert.Equal(t, len(originalTx.Calls), len(deserializedTx.Calls))
	assert.Equal(t, *originalTx.Calls[0].To, *deserializedTx.Calls[0].To)
	assert.Equal(t, originalTx.Calls[0].Value.Int64(), deserializedTx.Calls[0].Value.Int64())
	assert.NotNil(t, deserializedTx.Signature)

	recoveredAddr, err := transaction.VerifySignature(deserializedTx)
	require.NoError(t, err)
	assert.Equal(t, sender.Address(), recoveredAddr)
}
