package main

import (
	"context"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tempoxyz/tempo-go/pkg/client"
	"github.com/tempoxyz/tempo-go/pkg/signer"
	"github.com/tempoxyz/tempo-go/pkg/transaction"
)

const (
	// Anvil/Hardhat test account #0
	// Address: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
	testPrivateKey1 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

	// Anvil/Hardhat test account #1
	// Address: 0x70997970C51812dc3A010C7d01b50e0d17dc79C8
	testPrivateKey2 = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"

	// Anvil/Hardhat test account #2
	// Address: 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC
	feePayerPrivateKey = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"

	// AlphaUSD token address (for testnet)
	alphaUSDAddress = "0x20c0000000000000000000000000000000000001"

	// Native token (use for local dev node which is pre-funded with native tokens)
	nativeTokenAddress = "0x0000000000000000000000000000000000000000"
)

var (
	feeTokenAddress = alphaUSDAddress
)

var (
	rpcURL  string
	chainID = int64(1337) // Tempo dev mode default chain ID
)

func init() {
	// Require TEMPO_RPC_URL to be set to a real Tempo node
	rpcURL = os.Getenv("TEMPO_RPC_URL")
	if rpcURL == "" {
		panic("TEMPO_RPC_URL environment variable must be set to run integration tests. Example: export TEMPO_RPC_URL=https://rpc.testnet.tempo.xyz")
	}
}

// TestIntegration_SimpleTransaction tests creating, signing, and sending a simple transaction.
func TestIntegration_SimpleTransaction(t *testing.T) {
	ctx := context.Background()

	sender, err := signer.NewSigner(testPrivateKey1)
	require.NoError(t, err)

	recipient, err := signer.NewSigner(testPrivateKey2)
	require.NoError(t, err)

	t.Logf("Sender address: %s", sender.Address().Hex())
	t.Logf("Recipient address: %s", recipient.Address().Hex())

	rpcClient := client.New(rpcURL)

	// Get initial block number to verify node is running
	blockNum, err := rpcClient.GetBlockNumber(ctx)
	require.NoError(t, err)
	t.Logf("Current block number: %d", blockNum)

	nonce, err := rpcClient.GetTransactionCount(ctx, sender.Address().Hex())
	require.NoError(t, err)
	t.Logf("Sender nonce: %d", nonce)

	tx := transaction.NewBuilder(big.NewInt(chainID)).
		SetNonce(nonce).
		SetGas(100000).
		SetMaxFeePerGas(big.NewInt(10000000000)).
		SetMaxPriorityFeePerGas(big.NewInt(10000000000)).
		SetFeeToken(common.HexToAddress(feeTokenAddress)).
		AddCall(
			recipient.Address(),
			big.NewInt(0), // Send 0 value for testing
			[]byte{},
		).
		Build()

	err = transaction.SignTransaction(tx, sender)
	require.NoError(t, err)
	assert.NotNil(t, tx.Signature, "Transaction should be signed")

	recoveredAddr, err := transaction.VerifySignature(tx)
	require.NoError(t, err)
	assert.Equal(t, sender.Address(), recoveredAddr, "Recovered address should match sender")

	serialized, err := transaction.Serialize(tx, nil)
	require.NoError(t, err)
	assert.True(t, len(serialized) > 0, "Serialized transaction should not be empty")
	t.Logf("Serialized transaction: %s...", serialized[:50])

	txHash, err := rpcClient.SendRawTransaction(ctx, serialized)
	require.NoError(t, err)
	assert.True(t, len(txHash) > 0, "Transaction hash should not be empty")
	t.Logf("Transaction hash: %s", txHash)

	time.Sleep(2 * time.Second)

	newBlockNum, err := rpcClient.GetBlockNumber(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, newBlockNum, blockNum, "Block number should have increased")
	t.Logf("New block number: %d", newBlockNum)
}

// TestIntegration_BuilderValidation tests the BuildAndValidate method.
func TestIntegration_BuilderValidation(t *testing.T) {
	recipient := common.HexToAddress("0x1234567890123456789012345678901234567890")

	tx, err := transaction.NewBuilder(big.NewInt(chainID)).
		SetGas(100000).
		SetFeeToken(common.HexToAddress(feeTokenAddress)).
		AddCall(recipient, big.NewInt(0), []byte{}).
		BuildAndValidate()

	require.NoError(t, err)
	assert.NotNil(t, tx)

	_, err = transaction.NewBuilder(big.NewInt(chainID)).
		SetFeeToken(common.HexToAddress(feeTokenAddress)).
		AddCall(recipient, big.NewInt(0), []byte{}).
		BuildAndValidate()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "gas must be greater than 0")
}

// TestIntegration_TransactionClone tests the Clone method.
func TestIntegration_TransactionClone(t *testing.T) {
	recipient1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	recipient2 := common.HexToAddress("0x2222222222222222222222222222222222222222")

	template := transaction.NewBuilder(big.NewInt(chainID)).
		SetGas(100000).
		SetMaxFeePerGas(big.NewInt(10000000000)).
		SetFeeToken(common.HexToAddress(feeTokenAddress)).
		AddCall(recipient1, big.NewInt(1000), []byte{0xaa}).
		Build()

	cloned := template.Clone()
	require.NotNil(t, cloned)

	cloned.Calls[0].To = &recipient2
	cloned.Calls[0].Value = big.NewInt(2000)
	cloned.Calls[0].Data = []byte{0xbb}

	assert.Equal(t, recipient1, *template.Calls[0].To)
	assert.Equal(t, int64(1000), template.Calls[0].Value.Int64())
	assert.Equal(t, []byte{0xaa}, template.Calls[0].Data)

	assert.Equal(t, recipient2, *cloned.Calls[0].To)
	assert.Equal(t, int64(2000), cloned.Calls[0].Value.Int64())
	assert.Equal(t, []byte{0xbb}, cloned.Calls[0].Data)
}

// TestIntegration_FeePayerTransaction tests the fee payer pattern.
func TestIntegration_FeePayerTransaction(t *testing.T) {
	t.Skip("Skipping fee payer transaction test -- this does not work on the dev node yet")
	ctx := context.Background()

	sender, err := signer.NewSigner(testPrivateKey1)
	require.NoError(t, err)

	feePayer, err := signer.NewSigner(feePayerPrivateKey)
	require.NoError(t, err)

	recipient, err := signer.NewSigner(testPrivateKey2)
	require.NoError(t, err)

	t.Logf("Sender address: %s", sender.Address().Hex())
	t.Logf("Fee payer address: %s", feePayer.Address().Hex())
	t.Logf("Recipient address: %s", recipient.Address().Hex())

	rpcClient := client.New(rpcURL)

	nonce, err := rpcClient.GetTransactionCount(ctx, sender.Address().Hex())
	require.NoError(t, err)
	t.Logf("Sender nonce: %d", nonce)

	tx := transaction.NewBuilder(big.NewInt(chainID)).
		SetNonce(nonce).
		SetGas(100000).
		SetMaxFeePerGas(big.NewInt(10000000000)).
		SetMaxPriorityFeePerGas(big.NewInt(10000000000)).
		SetFeeToken(common.HexToAddress(feeTokenAddress)).
		AddCall(recipient.Address(), big.NewInt(0), []byte{}).
		Build()

	t.Logf("Fee token: %s", feeTokenAddress)

	err = transaction.SignTransaction(tx, sender)
	require.NoError(t, err)
	assert.NotNil(t, tx.Signature)

	senderAddr, err := transaction.VerifySignature(tx)
	require.NoError(t, err)
	assert.Equal(t, sender.Address(), senderAddr)

	err = transaction.AddFeePayerSignature(tx, feePayer)
	require.NoError(t, err)
	assert.NotNil(t, tx.FeePayerSignature)

	recoveredSender, recoveredFeePayer, err := transaction.VerifyDualSignatures(tx)
	require.NoError(t, err)
	assert.Equal(t, sender.Address(), recoveredSender)
	assert.Equal(t, feePayer.Address(), recoveredFeePayer)

	serialized, err := transaction.Serialize(tx, nil)
	require.NoError(t, err)
	t.Logf("Dual-signed transaction: %s", serialized)
	t.Logf("Has fee payer sig: %v", tx.FeePayerSignature != nil)

	txHash, err := rpcClient.SendRawTransaction(ctx, serialized)
	require.NoError(t, err)
	t.Logf("Transaction hash: %s", txHash)
}

// TestIntegration_BatchTransactions tests sending multiple transactions.
func TestIntegration_BatchTransactions(t *testing.T) {
	ctx := context.Background()

	sender, err := signer.NewSigner(testPrivateKey1)
	require.NoError(t, err)

	recipients := []common.Address{
		common.HexToAddress("0x1111111111111111111111111111111111111111"),
		common.HexToAddress("0x2222222222222222222222222222222222222222"),
		common.HexToAddress("0x3333333333333333333333333333333333333333"),
	}

	rpcClient := client.New(rpcURL)

	baseNonce, err := rpcClient.GetTransactionCount(ctx, sender.Address().Hex())
	require.NoError(t, err)

	var txHashes []string
	for i, recipient := range recipients {
		tx := transaction.NewBuilder(big.NewInt(chainID)).
			SetGas(100000).
			SetMaxFeePerGas(big.NewInt(10000000000)).
			SetMaxPriorityFeePerGas(big.NewInt(10000000000)).
			SetFeeToken(common.HexToAddress(feeTokenAddress)).
			SetNonce(baseNonce+uint64(i)).
			AddCall(recipient, big.NewInt(0), []byte{}).
			Build()

		err = transaction.SignTransaction(tx, sender)
		require.NoError(t, err)

		serialized, err := transaction.Serialize(tx, nil)
		require.NoError(t, err)

		txHash, err := rpcClient.SendRawTransaction(ctx, serialized)
		require.NoError(t, err)

		txHashes = append(txHashes, txHash)
		t.Logf("Transaction %d hash: %s", i+1, txHash)
	}

	assert.Equal(t, len(recipients), len(txHashes))
}

// TestIntegration_MultiCall tests transactions with multiple calls.
func TestIntegration_MultiCall(t *testing.T) {
	ctx := context.Background()

	sender, err := signer.NewSigner(testPrivateKey1)
	require.NoError(t, err)

	rpcClient := client.New(rpcURL)

	nonce, err := rpcClient.GetTransactionCount(ctx, sender.Address().Hex())
	require.NoError(t, err)

	tx := transaction.NewBuilder(big.NewInt(chainID)).
		SetNonce(nonce).
		SetGas(200000).
		SetMaxFeePerGas(big.NewInt(10000000000)).
		SetMaxPriorityFeePerGas(big.NewInt(10000000000)).
		SetFeeToken(common.HexToAddress(feeTokenAddress)).
		AddCall(
			common.HexToAddress("0x1111111111111111111111111111111111111111"),
			big.NewInt(0),
			[]byte{},
		).
		AddCall(
			common.HexToAddress("0x2222222222222222222222222222222222222222"),
			big.NewInt(0),
			[]byte{},
		).
		AddCall(
			common.HexToAddress("0x3333333333333333333333333333333333333333"),
			big.NewInt(0),
			[]byte{},
		).
		Build()

	assert.Equal(t, 3, len(tx.Calls), "Should have 3 calls")

	err = transaction.SignTransaction(tx, sender)
	require.NoError(t, err)

	serialized, err := transaction.Serialize(tx, nil)
	require.NoError(t, err)

	txHash, err := rpcClient.SendRawTransaction(ctx, serialized)
	require.NoError(t, err)
	t.Logf("Multi-call transaction hash: %s", txHash)
}

// TestIntegration_RoundTrip tests full serialization round-trip.
func TestIntegration_RoundTrip(t *testing.T) {
	sender, err := signer.NewSigner(testPrivateKey1)
	require.NoError(t, err)

	recipient := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Create and sign transaction
	originalTx := transaction.NewBuilder(big.NewInt(chainID)).
		SetGas(100000).
		SetMaxFeePerGas(big.NewInt(10000000000)).
		SetMaxPriorityFeePerGas(big.NewInt(10000000000)).
		SetFeeToken(common.HexToAddress(feeTokenAddress)).
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

// TestIntegration_Options tests client configuration options.
func TestIntegration_Options(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rpcClient := client.New(
		rpcURL,
		client.WithTimeout(10*time.Second),
	)

	blockNum, err := rpcClient.GetBlockNumber(ctx)
	require.NoError(t, err)
	assert.Greater(t, blockNum, uint64(0))
	t.Logf("Block number: %d", blockNum)
}
