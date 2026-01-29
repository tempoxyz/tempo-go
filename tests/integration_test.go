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
	// Native fee token (default)
	nativeFeeToken = common.HexToAddress("0x20c0000000000000000000000000000000000000")
	// AlphaUSD token address
	alphaUSD = common.HexToAddress("0x20C0000000000000000000000000000000000001")
	// BetaUSD token address
	betaUSD = common.HexToAddress("0x20C0000000000000000000000000000000000002")
	// ThetaUSD token address
	thetaUSD = common.HexToAddress("0x20C0000000000000000000000000000000000003")
	// Fee Controller precompile
	feeController = common.HexToAddress("0xfeec000000000000000000000000000000000000")
	// Account Keychain precompile
	accountKeychain = common.HexToAddress("0xAAAAAAAA00000000000000000000000000000000")
	// DEX precompile
	dex = common.HexToAddress("0xdec0000000000000000000000000000000000000")
	// Counter contract (deployed on testnet/devnet)
	counterContract = common.HexToAddress("0x86A2EE8FAf9A840F7a2c64CA3d51209F9A02081D")
	// LP Recipient for fee token liquidity
	lpRecipient = common.HexToAddress("0x6c4143BEd3A13cf9E5E43d45C60aD816FC091d0c")
)

// Function selectors
var (
	// increment() selector
	incrementSelector = mustDecodeHex("d09de08a")
	// mint(address,address,uint256,address) selector
	mintSelector = mustDecodeHex("f1aa8cb8")
	// setUserToken(address) selector
	setUserTokenSelector = mustDecodeHex("e7897444")
	// authorizeKey(address,uint8,uint64,bool,(address,uint256)[]) selector
	authorizeKeySelector = mustDecodeHex("54063a55")
)

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

var (
	rpcURL  string
	chainID int64
)

func init() {
	rpcURL = os.Getenv("TEMPO_RPC_URL")
	if rpcURL == "" {
		panic("TEMPO_RPC_URL environment variable must be set to run integration tests. Example: export TEMPO_RPC_URL=https://rpc.testnet.tempo.xyz")
	}
}

// waitForReceipt waits for a transaction receipt with retries and returns it
func waitForReceipt(t *testing.T, rpcClient *client.Client, txHash string) map[string]interface{} {
	t.Helper()
	ctx := context.Background()

	for i := 0; i < 15; i++ {
		time.Sleep(2 * time.Second)
		resp, err := rpcClient.SendRequest(ctx, "eth_getTransactionReceipt", txHash)
		if err == nil && resp.Result != nil {
			if receipt, ok := resp.Result.(map[string]interface{}); ok {
				return receipt
			}
		}
	}
	t.Logf("Warning: Receipt not available after 30 seconds for tx %s", txHash)
	return nil
}

// formatReceipt formats a transaction receipt for human-readable output (similar to cast)
func formatReceipt(t *testing.T, receipt map[string]interface{}) {
	t.Helper()
	if receipt == nil {
		t.Logf("Receipt not available")
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

	t.Logf("\n"+
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

// getChainID fetches and caches the chain ID from the RPC node.
func getChainID(t *testing.T, rpcClient *client.Client) int64 {
	t.Helper()
	if chainID != 0 {
		return chainID
	}
	ctx := context.Background()
	id, err := rpcClient.GetChainID(ctx)
	if err != nil {
		t.Fatalf("Failed to get chain ID: %v", err)
	}
	chainID = int64(id)
	t.Logf("Chain ID: %d", chainID)
	return chainID
}

// fundAddress funds an address using the tempo_fundAddress RPC
func fundAddress(t *testing.T, rpcClient *client.Client, address common.Address) {
	t.Helper()
	ctx := context.Background()

	for i := 0; i < 100; i++ {
		resp, err := rpcClient.SendRequest(ctx, "tempo_fundAddress", address.Hex())
		if err == nil && resp.Error == nil {
			if result, ok := resp.Result.([]interface{}); ok && len(result) > 0 {
				t.Logf("Funded address %s", address.Hex())
				time.Sleep(5 * time.Second) // Wait for blocks to mine
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Logf("Warning: Failed to fund address %s after 100 attempts", address.Hex())
}

// createAndFundSigner creates a new signer and funds it
func createAndFundSigner(t *testing.T, rpcClient *client.Client) *signer.Signer {
	t.Helper()
	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)
	s := signer.NewSignerFromKey(privateKey)
	fundAddress(t, rpcClient, s.Address())
	return s
}

// encodeCalldata encodes function selector + arguments
func encodeCalldata(selector []byte, args ...[]byte) []byte {
	result := make([]byte, len(selector))
	copy(result, selector)
	for _, arg := range args {
		result = append(result, arg...)
	}
	return result
}

// padLeft32 pads a byte slice to 32 bytes on the left
func padLeft32(b []byte) []byte {
	if len(b) >= 32 {
		return b[:32]
	}
	result := make([]byte, 32)
	copy(result[32-len(b):], b)
	return result
}

// addressToBytes32 converts an address to a 32-byte array
func addressToBytes32(addr common.Address) []byte {
	return padLeft32(addr.Bytes())
}

// uint256ToBytes32 converts a big.Int to a 32-byte array
func uint256ToBytes32(n *big.Int) []byte {
	return padLeft32(n.Bytes())
}

// getGasPrice fetches the current gas price from the network
func getGasPrice(t *testing.T, rpcClient *client.Client) *big.Int {
	t.Helper()
	ctx := context.Background()
	resp, err := rpcClient.SendRequest(ctx, "eth_gasPrice")
	if err != nil {
		// Fallback to high gas price
		return big.NewInt(50000000000) // 50 gwei
	}
	if resp.Error != nil {
		return big.NewInt(50000000000)
	}
	gasPriceHex, ok := resp.Result.(string)
	if !ok {
		return big.NewInt(50000000000)
	}
	gasPrice := new(big.Int)
	gasPrice.SetString(strings.TrimPrefix(gasPriceHex, "0x"), 16)
	// Add 50% buffer for priority
	gasPrice.Mul(gasPrice, big.NewInt(3))
	gasPrice.Div(gasPrice, big.NewInt(2))
	return gasPrice
}

// TestIntegration_NodeConnection tests basic node connectivity
func TestIntegration_NodeConnection(t *testing.T) {
	ctx := context.Background()
	rpcClient := client.New(rpcURL)

	t.Run("GetBlockNumber", func(t *testing.T) {
		blockNum, err := rpcClient.GetBlockNumber(ctx)
		require.NoError(t, err)
		// Dev node may have block 0, testnet/devnet will have higher
		assert.GreaterOrEqual(t, blockNum, uint64(0))
		t.Logf("Current block number: %d", blockNum)
	})

	t.Run("GetChainID", func(t *testing.T) {
		chainID, err := rpcClient.GetChainID(ctx)
		require.NoError(t, err)
		assert.Greater(t, chainID, uint64(0))
		t.Logf("Chain ID: %d", chainID)
	})

	t.Run("ClientVersion", func(t *testing.T) {
		resp, err := rpcClient.SendRequest(ctx, "web3_clientVersion")
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
	ctx := context.Background()
	rpcClient := client.New(rpcURL)
	cid := getChainID(t, rpcClient)
	gasPrice := getGasPrice(t, rpcClient)

	sender := createAndFundSigner(t, rpcClient)
	t.Logf("Sender address: %s", sender.Address().Hex())

	nonce, err := rpcClient.GetTransactionCount(ctx, sender.Address().Hex())
	require.NoError(t, err)

	tx := transaction.NewBuilder(big.NewInt(cid)).
		SetNonce(nonce).
		SetGas(300000).
		SetMaxFeePerGas(gasPrice).
		SetMaxPriorityFeePerGas(gasPrice).
		AddCall(counterContract, big.NewInt(0), incrementSelector).
		Build()

	err = transaction.SignTransaction(tx, sender)
	require.NoError(t, err)

	serialized, err := transaction.Serialize(tx, nil)
	require.NoError(t, err)

	txHash, err := rpcClient.SendRawTransaction(ctx, serialized)
	require.NoError(t, err)
	t.Logf("Transaction hash: %s", txHash)

	receipt := waitForReceipt(t, rpcClient, txHash)
	require.NotNil(t, receipt, "Failed to get receipt")
	status, _ := receipt["status"].(string)
	require.Equal(t, "0x1", status, "Transaction failed")
	formatReceipt(t, receipt)
}

// TestIntegration_FeeTokenLiquidity tests adding fee token liquidity
func TestIntegration_FeeTokenLiquidity(t *testing.T) {
	ctx := context.Background()
	rpcClient := client.New(rpcURL)
	cid := getChainID(t, rpcClient)
	gasPrice := getGasPrice(t, rpcClient)

	sender := createAndFundSigner(t, rpcClient)

	// Add liquidity for each fee token: AlphaUSD, BetaUSD, ThetaUSD
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
			nonce, err := rpcClient.GetTransactionCount(ctx, sender.Address().Hex())
			require.NoError(t, err)

			// mint(address token, address feeToken, uint256 amount, address recipient)
			calldata := encodeCalldata(
				mintSelector,
				addressToBytes32(ft.token),
				addressToBytes32(nativeFeeToken),
				uint256ToBytes32(big.NewInt(1000000000)),
				addressToBytes32(lpRecipient),
			)

			tx := transaction.NewBuilder(big.NewInt(cid)).
				SetNonce(nonce).
				SetGas(500000).
				SetMaxFeePerGas(gasPrice).
				SetMaxPriorityFeePerGas(gasPrice).
				AddCall(feeController, big.NewInt(0), calldata).
				Build()

			err = transaction.SignTransaction(tx, sender)
			require.NoError(t, err)

			serialized, err := transaction.Serialize(tx, nil)
			require.NoError(t, err)

			txHash, err := rpcClient.SendRawTransaction(ctx, serialized)
			require.NoError(t, err)
			t.Logf("%s liquidity tx hash: %s", ft.name, txHash)

			receipt := waitForReceipt(t, rpcClient, txHash)
			require.NotNil(t, receipt, "Failed to get receipt")
			status, _ := receipt["status"].(string)
			require.Equal(t, "0x1", status, "Transaction failed")
			formatReceipt(t, receipt)
		})
	}
}

// TestIntegration_SendWithFeeToken tests sending transactions with custom fee tokens
func TestIntegration_SendWithFeeToken(t *testing.T) {
	ctx := context.Background()
	rpcClient := client.New(rpcURL)
	cid := getChainID(t, rpcClient)
	gasPrice := getGasPrice(t, rpcClient)

	sender := createAndFundSigner(t, rpcClient)

	feeTokens := []struct {
		name  string
		token common.Address
	}{
		{"BetaUSD", betaUSD},
		{"ThetaUSD", thetaUSD},
	}

	for _, ft := range feeTokens {
		t.Run(ft.name, func(t *testing.T) {
			nonce, err := rpcClient.GetTransactionCount(ctx, sender.Address().Hex())
			require.NoError(t, err)

			tx := transaction.NewBuilder(big.NewInt(cid)).
				SetNonce(nonce).
				SetGas(300000).
				SetMaxFeePerGas(gasPrice).
				SetMaxPriorityFeePerGas(gasPrice).
				SetFeeToken(ft.token).
				AddCall(counterContract, big.NewInt(0), incrementSelector).
				Build()

			err = transaction.SignTransaction(tx, sender)
			require.NoError(t, err)

			serialized, err := transaction.Serialize(tx, nil)
			require.NoError(t, err)

			txHash, err := rpcClient.SendRawTransaction(ctx, serialized)
			require.NoError(t, err)
			t.Logf("Sent with %s fee token, tx hash: %s", ft.name, txHash)

			receipt := waitForReceipt(t, rpcClient, txHash)
			require.NotNil(t, receipt, "Failed to get receipt")
			status, _ := receipt["status"].(string)
			require.Equal(t, "0x1", status, "Transaction failed")
			formatReceipt(t, receipt)
		})
	}
}

// TestIntegration_2DNonces tests 2D nonce system (nonce_key)
func TestIntegration_2DNonces(t *testing.T) {
	ctx := context.Background()
	rpcClient := client.New(rpcURL)
	cid := getChainID(t, rpcClient)
	gasPrice := getGasPrice(t, rpcClient)

	sender := createAndFundSigner(t, rpcClient)

	// Use different nonce keys for parallel transaction lanes
	nonceKeys := []int64{1, 2, 3}

	for _, key := range nonceKeys {
		t.Run(fmt.Sprintf("NonceKey_%d", key), func(t *testing.T) {
			// Each nonce key starts at 0
			tx := transaction.NewBuilder(big.NewInt(cid)).
				SetNonce(0).
				SetNonceKey(big.NewInt(key)).
				SetGas(300000).
				SetMaxFeePerGas(gasPrice).
				SetMaxPriorityFeePerGas(gasPrice).
				AddCall(counterContract, big.NewInt(0), incrementSelector).
				Build()

			err := transaction.SignTransaction(tx, sender)
			require.NoError(t, err)

			serialized, err := transaction.Serialize(tx, nil)
			require.NoError(t, err)

			txHash, err := rpcClient.SendRawTransaction(ctx, serialized)
			require.NoError(t, err)
			t.Logf("2D nonce (key=%d) tx hash: %s", key, txHash)

			receipt := waitForReceipt(t, rpcClient, txHash)
			require.NotNil(t, receipt, "Failed to get receipt")
			status, _ := receipt["status"].(string)
			require.Equal(t, "0x1", status, "Transaction failed")
			formatReceipt(t, receipt)
		})
	}
}

// TestIntegration_ExpiringNonces tests expiring nonces (valid_before, valid_after)
func TestIntegration_ExpiringNonces(t *testing.T) {
	ctx := context.Background()
	rpcClient := client.New(rpcURL)
	cid := getChainID(t, rpcClient)
	gasPrice := getGasPrice(t, rpcClient)

	sender := createAndFundSigner(t, rpcClient)

	t.Run("ValidBefore", func(t *testing.T) {
		// Transaction valid for next 25 seconds
		validBefore := uint64(time.Now().Unix() + 25)

		tx := transaction.NewBuilder(big.NewInt(cid)).
			SetNonce(0).
			SetNonceKey(big.NewInt(100)). // Use unique nonce key
			SetValidBefore(validBefore).
			SetGas(300000).
			SetMaxFeePerGas(gasPrice).
			SetMaxPriorityFeePerGas(gasPrice).
			AddCall(counterContract, big.NewInt(0), incrementSelector).
			Build()

		err := transaction.SignTransaction(tx, sender)
		require.NoError(t, err)

		serialized, err := transaction.Serialize(tx, nil)
		require.NoError(t, err)

		txHash, err := rpcClient.SendRawTransaction(ctx, serialized)
		require.NoError(t, err)
		t.Logf("Expiring nonce (validBefore=%d) tx hash: %s", validBefore, txHash)

		receipt := waitForReceipt(t, rpcClient, txHash)
		require.NotNil(t, receipt, "Failed to get receipt")
		status, _ := receipt["status"].(string)
		require.Equal(t, "0x1", status, "Transaction failed")
		formatReceipt(t, receipt)
	})

	t.Run("ValidAfterAndBefore", func(t *testing.T) {
		// Transaction valid after now, before now+25s
		now := time.Now().Unix()
		validAfter := uint64(now - 1)
		validBefore := uint64(now + 25)

		tx := transaction.NewBuilder(big.NewInt(cid)).
			SetNonce(0).
			SetNonceKey(big.NewInt(101)). // Use unique nonce key
			SetValidAfter(validAfter).
			SetValidBefore(validBefore).
			SetGas(300000).
			SetMaxFeePerGas(gasPrice).
			SetMaxPriorityFeePerGas(gasPrice).
			AddCall(counterContract, big.NewInt(0), incrementSelector).
			Build()

		err := transaction.SignTransaction(tx, sender)
		require.NoError(t, err)

		serialized, err := transaction.Serialize(tx, nil)
		require.NoError(t, err)

		txHash, err := rpcClient.SendRawTransaction(ctx, serialized)
		require.NoError(t, err)
		t.Logf("Expiring nonce (validAfter=%d, validBefore=%d) tx hash: %s", validAfter, validBefore, txHash)

		receipt := waitForReceipt(t, rpcClient, txHash)
		require.NotNil(t, receipt, "Failed to get receipt")
		status, _ := receipt["status"].(string)
		require.Equal(t, "0x1", status, "Transaction failed")
		formatReceipt(t, receipt)
	})
}

// TestIntegration_SponsoredTransaction tests sponsored (gasless) transactions
func TestIntegration_SponsoredTransaction(t *testing.T) {
	ctx := context.Background()
	rpcClient := client.New(rpcURL)
	cid := getChainID(t, rpcClient)
	gasPrice := getGasPrice(t, rpcClient)

	sender := createAndFundSigner(t, rpcClient)
	sponsor := createAndFundSigner(t, rpcClient)

	t.Logf("Sender address: %s", sender.Address().Hex())
	t.Logf("Sponsor address: %s", sponsor.Address().Hex())

	// Create transaction with awaiting_fee_payer flag
	tx := transaction.NewBuilder(big.NewInt(cid)).
		SetNonce(0).
		SetNonceKey(big.NewInt(200)). // Use unique nonce key
		SetGas(300000).
		SetMaxFeePerGas(gasPrice).
		SetMaxPriorityFeePerGas(gasPrice).
		AddCall(counterContract, big.NewInt(0), incrementSelector).
		Build()

	tx.AwaitingFeePayer = true

	// Sign as sender
	err := transaction.SignTransaction(tx, sender)
	require.NoError(t, err)

	// Add fee payer signature
	err = transaction.AddFeePayerSignature(tx, sponsor)
	require.NoError(t, err)

	// Verify dual signatures
	recoveredSender, recoveredSponsor, err := transaction.VerifyDualSignatures(tx)
	require.NoError(t, err)
	assert.Equal(t, sender.Address(), recoveredSender)
	assert.Equal(t, sponsor.Address(), recoveredSponsor)

	serialized, err := transaction.Serialize(tx, nil)
	require.NoError(t, err)

	txHash, err := rpcClient.SendRawTransaction(ctx, serialized)
	require.NoError(t, err)
	t.Logf("Sponsored transaction hash: %s", txHash)

	receipt := waitForReceipt(t, rpcClient, txHash)
	require.NotNil(t, receipt, "Failed to get receipt")
	status, _ := receipt["status"].(string)
	require.Equal(t, "0x1", status, "Sponsored transaction failed")
	formatReceipt(t, receipt)

	// Verify the fee payer in receipt matches sponsor
	feePayer, _ := receipt["feePayer"].(string)
	assert.True(t, strings.EqualFold(feePayer, sponsor.Address().Hex()),
		"Expected feePayer %s, got %s", sponsor.Address().Hex(), feePayer)
}

// TestIntegration_AccessKeys tests access key (keychain) signing
func TestIntegration_AccessKeys(t *testing.T) {

	ctx := context.Background()
	rpcClient := client.New(rpcURL)
	cid := getChainID(t, rpcClient)

	// Create root account and access key
	rootAccount := createAndFundSigner(t, rpcClient)
	accessKeyPriv, err := crypto.GenerateKey()
	require.NoError(t, err)
	accessKey := signer.NewSignerFromKey(accessKeyPriv)

	t.Logf("Root account: %s", rootAccount.Address().Hex())
	t.Logf("Access key: %s", accessKey.Address().Hex())

	// Get gas price for transactions
	gasPrice := getGasPrice(t, rpcClient)
	t.Logf("Using gas price: %s", gasPrice.String())

	// First, authorize the access key on-chain using EIP-1559 tx (not Tempo tx)
	t.Run("AuthorizeAccessKey", func(t *testing.T) {
		nonce, err := rpcClient.GetTransactionCount(ctx, rootAccount.Address().Hex())
		require.NoError(t, err)

		// authorizeKey(address key, uint8 sigType, uint64 expiry, bool enforceLimits, (address,uint256)[] limits)
		// sigType: 0 = Secp256k1, expiry: 1893456000 (year 2030), enforceLimits: false
		calldata := encodeCalldata(
			authorizeKeySelector,
			addressToBytes32(accessKey.Address()),
			padLeft32([]byte{0}),                     // sigType = 0 (Secp256k1)
			uint256ToBytes32(big.NewInt(1893456000)), // expiry
			padLeft32([]byte{0}),                     // enforceLimits = false
			uint256ToBytes32(big.NewInt(0xa0)),       // offset to limits array
			uint256ToBytes32(big.NewInt(0)),          // limits array length = 0
		)

		// Use standard EIP-1559 transaction for authorization
		// Gas estimate is ~532000, use 600000 for safety
		eip1559Tx := types.NewTx(&types.DynamicFeeTx{
			ChainID:   big.NewInt(cid),
			Nonce:     nonce,
			GasTipCap: gasPrice,
			GasFeeCap: gasPrice,
			Gas:       600000,
			To:        &accountKeychain,
			Value:     big.NewInt(0),
			Data:      calldata,
		})

		signedTx, err := types.SignTx(eip1559Tx, types.NewLondonSigner(big.NewInt(cid)), rootAccount.PrivateKey())
		require.NoError(t, err)

		txBytes, err := signedTx.MarshalBinary()
		require.NoError(t, err)

		txHash, err := rpcClient.SendRawTransaction(ctx, "0x"+hex.EncodeToString(txBytes))
		require.NoError(t, err)
		t.Logf("Authorize access key tx hash: %s", txHash)

		receipt := waitForReceipt(t, rpcClient, txHash)
		require.NotNil(t, receipt, "Failed to get authorization receipt")
		status, _ := receipt["status"].(string)
		require.Equal(t, "0x1", status, "Authorization tx failed")
		t.Logf("Authorization tx succeeded")
		formatReceipt(t, receipt)
	})

	// Access key doesn't need funding - it signs on behalf of root account
	// But we wait a bit more to ensure authorization is fully propagated
	time.Sleep(3 * time.Second)

	// Now use the access key to sign a transaction
	t.Run("SignWithAccessKey", func(t *testing.T) {
		tx := transaction.NewBuilder(big.NewInt(cid)).
			SetNonce(0).
			SetNonceKey(big.NewInt(300)). // Use unique nonce key
			SetGas(500000).
			SetMaxFeePerGas(gasPrice).
			SetMaxPriorityFeePerGas(gasPrice).
			AddCall(counterContract, big.NewInt(0), incrementSelector).
			Build()

		err := keychain.SignWithAccessKey(tx, accessKey, rootAccount.Address())
		require.NoError(t, err)

		// Verify the access key signature
		recoveredAccessKey, recoveredRoot, err := keychain.VerifyAccessKeySignature(tx)
		require.NoError(t, err)
		assert.Equal(t, accessKey.Address(), recoveredAccessKey)
		assert.Equal(t, rootAccount.Address(), recoveredRoot)

		serialized, err := transaction.Serialize(tx, nil)
		require.NoError(t, err)

		txHash, err := rpcClient.SendRawTransaction(ctx, serialized)
		require.NoError(t, err)
		t.Logf("Access key signed tx hash: %s", txHash)

		receipt := waitForReceipt(t, rpcClient, txHash)
		require.NotNil(t, receipt, "Failed to get receipt")
		status, _ := receipt["status"].(string)
		require.Equal(t, "0x1", status, "Access key transaction failed")
		formatReceipt(t, receipt)
	})
}

// TestIntegration_BatchTransactions tests transactions with multiple calls
func TestIntegration_BatchTransactions(t *testing.T) {
	ctx := context.Background()
	rpcClient := client.New(rpcURL)
	cid := getChainID(t, rpcClient)
	gasPrice := getGasPrice(t, rpcClient)

	sender := createAndFundSigner(t, rpcClient)

	t.Run("TwoCalls", func(t *testing.T) {
		nonce, err := rpcClient.GetTransactionCount(ctx, sender.Address().Hex())
		require.NoError(t, err)

		tx := transaction.NewBuilder(big.NewInt(cid)).
			SetNonce(nonce).
			SetGas(300000).
			SetMaxFeePerGas(gasPrice).
			SetMaxPriorityFeePerGas(gasPrice).
			AddCall(counterContract, big.NewInt(0), incrementSelector).
			AddCall(counterContract, big.NewInt(0), incrementSelector).
			Build()

		err = transaction.SignTransaction(tx, sender)
		require.NoError(t, err)

		serialized, err := transaction.Serialize(tx, nil)
		require.NoError(t, err)

		txHash, err := rpcClient.SendRawTransaction(ctx, serialized)
		require.NoError(t, err)
		t.Logf("Batch (2 calls) tx hash: %s", txHash)

		receipt := waitForReceipt(t, rpcClient, txHash)
		require.NotNil(t, receipt, "Failed to get receipt")
		status, _ := receipt["status"].(string)
		require.Equal(t, "0x1", status, "Batch transaction failed")
		formatReceipt(t, receipt)
	})

	t.Run("ThreeCalls", func(t *testing.T) {
		nonce, err := rpcClient.GetTransactionCount(ctx, sender.Address().Hex())
		require.NoError(t, err)

		tx := transaction.NewBuilder(big.NewInt(cid)).
			SetNonce(nonce).
			SetGas(300000).
			SetMaxFeePerGas(gasPrice).
			SetMaxPriorityFeePerGas(gasPrice).
			AddCall(counterContract, big.NewInt(0), incrementSelector).
			AddCall(counterContract, big.NewInt(0), incrementSelector).
			AddCall(counterContract, big.NewInt(0), incrementSelector).
			Build()

		err = transaction.SignTransaction(tx, sender)
		require.NoError(t, err)

		serialized, err := transaction.Serialize(tx, nil)
		require.NoError(t, err)

		txHash, err := rpcClient.SendRawTransaction(ctx, serialized)
		require.NoError(t, err)
		t.Logf("Batch (3 calls) tx hash: %s", txHash)

		receipt := waitForReceipt(t, rpcClient, txHash)
		require.NotNil(t, receipt, "Failed to get receipt")
		status, _ := receipt["status"].(string)
		require.Equal(t, "0x1", status, "Batch transaction failed")
		formatReceipt(t, receipt)
	})
}

// TestIntegration_SetUserFeeToken tests setting user's default fee token
func TestIntegration_SetUserFeeToken(t *testing.T) {
	ctx := context.Background()
	rpcClient := client.New(rpcURL)
	cid := getChainID(t, rpcClient)
	gasPrice := getGasPrice(t, rpcClient)

	sender := createAndFundSigner(t, rpcClient)

	t.Run("SetToBetaUSD", func(t *testing.T) {
		nonce, err := rpcClient.GetTransactionCount(ctx, sender.Address().Hex())
		require.NoError(t, err)

		calldata := encodeCalldata(setUserTokenSelector, addressToBytes32(betaUSD))

		tx := transaction.NewBuilder(big.NewInt(cid)).
			SetNonce(nonce).
			SetGas(600000).
			SetMaxFeePerGas(gasPrice).
			SetMaxPriorityFeePerGas(gasPrice).
			AddCall(feeController, big.NewInt(0), calldata).
			Build()

		err = transaction.SignTransaction(tx, sender)
		require.NoError(t, err)

		serialized, err := transaction.Serialize(tx, nil)
		require.NoError(t, err)

		txHash, err := rpcClient.SendRawTransaction(ctx, serialized)
		require.NoError(t, err)
		t.Logf("Set user fee token to BetaUSD tx hash: %s", txHash)

		receipt := waitForReceipt(t, rpcClient, txHash)
		require.NotNil(t, receipt, "Failed to get receipt")
		status, _ := receipt["status"].(string)
		require.Equal(t, "0x1", status, "SetUserFeeToken failed")
		formatReceipt(t, receipt)
	})

	t.Run("ResetToNative", func(t *testing.T) {
		nonce, err := rpcClient.GetTransactionCount(ctx, sender.Address().Hex())
		require.NoError(t, err)

		calldata := encodeCalldata(setUserTokenSelector, addressToBytes32(nativeFeeToken))

		tx := transaction.NewBuilder(big.NewInt(cid)).
			SetNonce(nonce).
			SetGas(600000).
			SetMaxFeePerGas(gasPrice).
			SetMaxPriorityFeePerGas(gasPrice).
			AddCall(feeController, big.NewInt(0), calldata).
			Build()

		err = transaction.SignTransaction(tx, sender)
		require.NoError(t, err)

		serialized, err := transaction.Serialize(tx, nil)
		require.NoError(t, err)

		txHash, err := rpcClient.SendRawTransaction(ctx, serialized)
		require.NoError(t, err)
		t.Logf("Reset user fee token to native tx hash: %s", txHash)

		receipt := waitForReceipt(t, rpcClient, txHash)
		require.NotNil(t, receipt, "Failed to get receipt")
		status, _ := receipt["status"].(string)
		require.Equal(t, "0x1", status, "ResetUserFeeToken failed")
		formatReceipt(t, receipt)
	})
}

// TestIntegration_DEXOperations tests DEX operations (skipped - require liquidity setup)
func TestIntegration_DEXOperations(t *testing.T) {
	t.Skip("DEX operations require liquidity setup - works with full tempo-check.sh flow")

	// TODO: Implement DEX tests when liquidity setup is available:
	// - Approve DEX
	// - Place bid
	// - Place ask
	// - Place flip
	// - Swap exact amount in
	// - Swap exact amount out
}

// TestIntegration_BuilderValidation tests the BuildAndValidate method
func TestIntegration_BuilderValidation(t *testing.T) {
	rpcClient := client.New(rpcURL)
	cid := getChainID(t, rpcClient)

	recipient := common.HexToAddress("0x1234567890123456789012345678901234567890")

	tx, err := transaction.NewBuilder(big.NewInt(cid)).
		SetGas(300000).
		AddCall(recipient, big.NewInt(0), []byte{}).
		BuildAndValidate()

	require.NoError(t, err)
	assert.NotNil(t, tx)

	_, err = transaction.NewBuilder(big.NewInt(cid)).
		AddCall(recipient, big.NewInt(0), []byte{}).
		BuildAndValidate()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "gas must be greater than 0")
}

// TestIntegration_RoundTrip tests full serialization round-trip
func TestIntegration_RoundTrip(t *testing.T) {
	rpcClient := client.New(rpcURL)
	cid := getChainID(t, rpcClient)

	senderPriv, err := crypto.GenerateKey()
	require.NoError(t, err)
	sender := signer.NewSignerFromKey(senderPriv)

	recipient := common.HexToAddress("0x1234567890123456789012345678901234567890")

	originalTx := transaction.NewBuilder(big.NewInt(cid)).
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
