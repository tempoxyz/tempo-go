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
	authorizeKeySelector = mustDecodeSelector(keychain.AuthorizeKeySelector)
	getKeySelector       = mustDecodeSelector(keychain.GetKeySelector)
	revokeKeySelector    = mustDecodeSelector(keychain.RevokeKeySelector)
)

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// mustDecodeSelector strips the "0x" prefix from a selector constant and decodes it.
func mustDecodeSelector(sel string) []byte {
	return mustDecodeHex(strings.TrimPrefix(sel, "0x"))
}

var rpcURL string
var hardfork string

func init() {
	rpcURL = os.Getenv("TEMPO_RPC_URL")
	if rpcURL == "" {
		panic("TEMPO_RPC_URL environment variable must be set to run integration tests. Example: export TEMPO_RPC_URL=https://rpc.moderato.tempo.xyz")
	}
	hardfork = os.Getenv("TEMPO_HARDFORK")
	if hardfork == "" {
		hardfork = "T3"
	}
}

func isT2() bool {
	return hardfork == "T2"
}

func isT5OrLater() bool {
	switch hardfork {
	case "T5", "T6":
		return true
	default:
		return false
	}
}

func isT6OrLater() bool {
	return hardfork == "T6"
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

// devKeyPrivate is the well-known dev account private key used for local devnet funding.
const devKeyPrivate = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

// farFutureKeyExpiry is valid whether a live node reports timestamps in
// seconds or milliseconds.
const farFutureKeyExpiry = int64(1<<63 - 1)

// erc20TransferSelector is the function selector for transfer(address,uint256).
var erc20TransferSelector = mustDecodeHex("a9059cbb")

// fundAddress funds an address and waits for tx receipts and balance confirmation.
// It first tries tempo_fundAddress (available on testnet), then falls back to a
// TIP-20 transfer from the dev account (for local Docker devnets).
func (tc *testContext) fundAddress(address common.Address) {
	tc.t.Helper()

	// Try tempo_fundAddress first
	resp, err := tc.client.SendRequest(tc.ctx, "tempo_fundAddress", address.Hex())
	if err == nil && resp.Error == nil && resp.Result != nil {
		switch result := resp.Result.(type) {
		case []interface{}:
			if len(result) > 0 {
				tc.t.Logf("Funded address %s via tempo_fundAddress", address.Hex())
				for _, h := range result {
					if hash, ok := h.(string); ok {
						tc.waitForReceipt(hash)
					}
				}
				tc.waitForBalance(address)
				return
			}
		case string:
			if result != "" {
				tc.t.Logf("Funded address %s via tempo_fundAddress", address.Hex())
				tc.waitForReceipt(result)
				tc.waitForBalance(address)
				return
			}
		}
	}

	// Fallback: fund via TIP-20 transfer from the dev account
	tc.t.Logf("tempo_fundAddress unavailable, funding %s via dev account TIP-20 transfer", address.Hex())
	devSigner, err := signer.NewSigner(devKeyPrivate)
	require.NoError(tc.t, err)

	// Build ERC-20 transfer(address,uint256) calldata to the native fee token
	fundAmount := new(big.Int).Mul(big.NewInt(1000000000), big.NewInt(1000000000)) // 1e18
	transferCalldata := encodeCalldata(
		erc20TransferSelector,
		addressToBytes32(address),
		uint256ToBytes32(fundAmount),
	)

	nonce := tc.getNonce(devSigner.Address())
	tx := tc.newTxBuilder().
		SetNonce(nonce).
		SetGas(100000).
		AddCall(nativeFeeToken, big.NewInt(0), transferCalldata).
		Build()

	err = transaction.SignTransaction(tx, devSigner)
	require.NoError(tc.t, err)

	serialized, err := transaction.Serialize(tx, nil)
	require.NoError(tc.t, err)

	txHash, err := tc.client.SendRawTransaction(tc.ctx, serialized)
	require.NoError(tc.t, err)
	tc.t.Logf("Funding tx hash: %s", txHash)

	tc.waitForReceipt(txHash)
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

// getTransactionByHash fetches a transaction from the node.
func (tc *testContext) getTransactionByHash(txHash string) map[string]interface{} {
	tc.t.Helper()
	resp, err := tc.client.SendRequest(tc.ctx, "eth_getTransactionByHash", txHash)
	require.NoError(tc.t, err)
	require.NoError(tc.t, resp.CheckError())

	txObj, ok := resp.Result.(map[string]interface{})
	require.True(tc.t, ok, "expected transaction object result, got %T", resp.Result)
	return txObj
}

// getFirstCallData extracts calldata from a fetched transaction.
// Tempo transactions may expose calldata either as top-level input or within the first call.
func getFirstCallData(txObj map[string]interface{}) (string, bool) {
	if input, ok := txObj["input"].(string); ok && input != "" && input != "0x" {
		return input, true
	}

	calls, ok := txObj["calls"].([]interface{})
	if !ok || len(calls) == 0 {
		return "", false
	}

	call, ok := calls[0].(map[string]interface{})
	if !ok {
		return "", false
	}
	if data, ok := call["data"].(string); ok && data != "" {
		return data, true
	}
	if input, ok := call["input"].(string); ok && input != "" {
		return input, true
	}
	return "", false
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

// TestIntegration_TIP20Selectors tests that TIP-20 calldata on a local node matches the selector constants.
func TestIntegration_TIP20Selectors(t *testing.T) {
	tc := newTestContext(t)
	sender := tc.createAndFundSigner()
	recipient := tc.createAndFundSigner()
	memo := mustDecodeHex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	amount := big.NewInt(1)
	approvalAmount := big.NewInt(12345)

	tests := []struct {
		name     string
		selector [4]byte
		build    func() []byte
	}{
		{
			name:     "transfer",
			selector: keychain.SelectorTransfer,
			build: func() []byte {
				data, err := transaction.EncodeTIP20TransferData(recipient.Address(), amount)
				require.NoError(t, err)
				return data
			},
		},
		{
			name:     "approve",
			selector: keychain.SelectorApprove,
			build: func() []byte {
				return encodeCalldata(
					keychain.SelectorApprove[:],
					addressToBytes32(recipient.Address()),
					uint256ToBytes32(approvalAmount),
				)
			},
		},
		{
			name:     "transferWithMemo",
			selector: keychain.SelectorTransferWithMemo,
			build: func() []byte {
				data, err := transaction.EncodeTIP20TransferWithMemoData(recipient.Address(), amount, memo)
				require.NoError(t, err)
				return data
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calldata := tt.build()
			tx := tc.newTxBuilder().
				SetNonce(tc.getNonce(sender.Address())).
				SetGas(300000).
				AddCall(nativeFeeToken, big.NewInt(0), calldata).
				Build()

			err := transaction.SignTransaction(tx, sender)
			require.NoError(t, err)

			receipt, txHash := tc.sendTx(tx)
			require.NotNil(t, receipt, "failed to get receipt")
			status, _ := receipt["status"].(string)
			require.Equal(t, "0x1", status, "transaction failed")

			fetchedTx := tc.getTransactionByHash(txHash)
			callData, ok := getFirstCallData(fetchedTx)
			require.True(t, ok, "expected calldata in transaction response: %#v", fetchedTx)

			expectedSelector := "0x" + hex.EncodeToString(tt.selector[:])
			assert.True(t, strings.HasPrefix(strings.ToLower(callData), strings.ToLower(expectedSelector)), "expected calldata %s to start with selector %s", callData, expectedSelector)
			assert.Equal(t, strings.ToLower("0x"+hex.EncodeToString(calldata)), strings.ToLower(callData), "node returned unexpected calldata")
		})
	}
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

	// Create sponsored transaction using SetSponsored() builder method
	tx := tc.newTxBuilder().
		SetNonce(0).
		SetNonceKey(big.NewInt(200)).
		SetGas(300000).
		AddCall(counterContract, big.NewInt(0), incrementSelector).
		SetSponsored(true).
		Build()

	// Sign as sender
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
		calldata := buildAuthorizeKeyCalldata(accessKey.Address(), farFutureKeyExpiry, false)

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

// callGetKey calls the getKey precompile and returns the raw result bytes.
func (tc *testContext) callGetKey(account, keyId common.Address) []byte {
	tc.t.Helper()
	getKeyCalldata := encodeCalldata(
		getKeySelector,
		addressToBytes32(account),
		addressToBytes32(keyId),
	)

	resp, err := tc.client.SendRequest(tc.ctx, "eth_call", map[string]interface{}{
		"to":   accountKeychain.Hex(),
		"data": "0x" + hex.EncodeToString(getKeyCalldata),
	}, "latest")
	require.NoError(tc.t, err)
	require.Nil(tc.t, resp.Error, "eth_call failed: %v", resp.Error)

	result, ok := resp.Result.(string)
	require.True(tc.t, ok, "expected string result")
	require.True(tc.t, len(result) > 2, "expected non-empty result from getKey")

	resultBytes, err := hex.DecodeString(strings.TrimPrefix(result, "0x"))
	require.NoError(tc.t, err)
	require.True(tc.t, len(resultBytes) >= 160, "getKey result too short, expected >= 160 bytes, got %d", len(resultBytes))
	return resultBytes
}

// parseKeyInfoKeyId extracts the keyId from a getKey result.
// KeyInfo layout: signatureType (32) | keyId (32) | expiry (32) | enforceLimits (32) | isRevoked (32)
func parseKeyInfoKeyId(resultBytes []byte) common.Address {
	return common.BytesToAddress(resultBytes[32+12 : 64])
}

// parseKeyInfoIsRevoked extracts the isRevoked boolean from a getKey result.
func parseKeyInfoIsRevoked(resultBytes []byte) bool {
	// isRevoked is the 5th word (offset 128-160); treat any non-zero value as true
	for _, b := range resultBytes[128:160] {
		if b != 0 {
			return true
		}
	}
	return false
}

// parseABIEncodedBool extracts a Solidity bool return value.
func parseABIEncodedBool(t *testing.T, result string) bool {
	t.Helper()
	resultBytes, err := hex.DecodeString(strings.TrimPrefix(result, "0x"))
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(resultBytes), 32, "bool result too short")
	for _, b := range resultBytes[len(resultBytes)-32:] {
		if b != 0 {
			return true
		}
	}
	return false
}

// TestIntegration_KeychainSelectors tests that keychain selectors work against the precompile
func TestIntegration_KeychainSelectors(t *testing.T) {
	tc := newTestContext(t)

	rootAccount := tc.createAndFundSigner()
	accessKeyPriv, err := crypto.GenerateKey()
	require.NoError(t, err)
	accessKey := signer.NewSignerFromKey(accessKeyPriv)

	expiry := farFutureKeyExpiry

	t.Logf("Root account: %s", rootAccount.Address().Hex())
	t.Logf("Access key: %s", accessKey.Address().Hex())

	// Step 1: Authorize the key with enforceLimits=false, empty TokenLimit[]
	authCalldata := buildAuthorizeKeyCalldata(accessKey.Address(), expiry, false)

	authTx := tc.newTxBuilder().
		SetNonce(tc.getNonce(rootAccount.Address())).
		SetGas(600000).
		AddCall(accountKeychain, big.NewInt(0), authCalldata).
		Build()

	err = transaction.SignTransaction(authTx, rootAccount)
	require.NoError(t, err)

	receipt := tc.sendTxExpectSuccess(authTx, "Authorization tx failed")
	require.NotNil(t, receipt)

	time.Sleep(3 * time.Second)

	// Step 2: Call getKey to verify the key was stored
	t.Run("GetKey", func(t *testing.T) {
		resultBytes := tc.callGetKey(rootAccount.Address(), accessKey.Address())

		recoveredKeyId := parseKeyInfoKeyId(resultBytes)
		assert.Equal(t, accessKey.Address(), recoveredKeyId, "getKey returned wrong keyId")
		assert.False(t, parseKeyInfoIsRevoked(resultBytes), "key should not be revoked yet")

		t.Logf("getKey returned keyId: %s", recoveredKeyId.Hex())
	})

	// Step 3: Revoke the key and verify
	t.Run("RevokeKey", func(t *testing.T) {
		revokeCalldata := encodeCalldata(
			revokeKeySelector,
			addressToBytes32(accessKey.Address()),
		)

		revokeTx := tc.newTxBuilder().
			SetNonce(tc.getNonce(rootAccount.Address())).
			SetGas(600000).
			AddCall(accountKeychain, big.NewInt(0), revokeCalldata).
			Build()

		err := transaction.SignTransaction(revokeTx, rootAccount)
		require.NoError(t, err)

		tc.sendTxExpectSuccess(revokeTx, "Revoke tx failed")

		time.Sleep(2 * time.Second)

		resultBytes := tc.callGetKey(rootAccount.Address(), accessKey.Address())
		assert.True(t, parseKeyInfoIsRevoked(resultBytes), "expected key to be revoked")

		t.Logf("Key revoked successfully")
	})
}

// TestIntegration_T5KeyAuthorizationWitness tests TIP-1053 witness APIs.
func TestIntegration_T5KeyAuthorizationWitness(t *testing.T) {
	if !isT5OrLater() {
		t.Skip("requires TEMPO_HARDFORK=T5 or later and a T5-capable RPC")
	}

	tc := newTestContext(t)

	rootAccount := tc.createAndFundSigner()
	accessKeyPriv, err := crypto.GenerateKey()
	require.NoError(t, err)
	accessKey := signer.NewSignerFromKey(accessKeyPriv)

	burnWitness := crypto.Keccak256Hash([]byte("tempo-go integration burn witness"), rootAccount.Address().Bytes())
	authWitness := crypto.Keccak256Hash([]byte("tempo-go integration auth witness"), rootAccount.Address().Bytes(), accessKey.Address().Bytes())

	t.Logf("Root account: %s", rootAccount.Address().Hex())
	t.Logf("Access key: %s", accessKey.Address().Hex())

	sendKeychainCall := func(t *testing.T, call keychain.Call, msg string) {
		t.Helper()
		tx := tc.newTxBuilder().
			SetNonce(tc.getNonce(rootAccount.Address())).
			SetGas(600000).
			AddCall(call.To, big.NewInt(0), call.Data).
			Build()

		err := transaction.SignTransaction(tx, rootAccount)
		require.NoError(t, err)

		tc.sendTxExpectSuccess(tx, msg)
	}

	isWitnessBurned := func(t *testing.T, witness common.Hash) bool {
		t.Helper()
		call, err := keychain.IsKeyAuthorizationWitnessBurned(rootAccount.Address(), witness)
		require.NoError(t, err)

		resp, err := tc.client.SendRequest(tc.ctx, "eth_call", map[string]interface{}{
			"to":   call.To.Hex(),
			"data": "0x" + hex.EncodeToString(call.Data),
		}, "latest")
		require.NoError(t, err)
		require.Nil(t, resp.Error, "isKeyAuthorizationWitnessBurned eth_call failed: %v", resp.Error)

		result, ok := resp.Result.(string)
		require.True(t, ok, "expected string result")
		return parseABIEncodedBool(t, result)
	}

	t.Run("BurnWitness", func(t *testing.T) {
		call, err := keychain.BurnKeyAuthorizationWitness(burnWitness)
		require.NoError(t, err)

		sendKeychainCall(t, call, "burnKeyAuthorizationWitness failed")
	})

	t.Run("ReadBurnedWitnessState", func(t *testing.T) {
		assert.True(t, isWitnessBurned(t, burnWitness), "expected burned witness to be marked burned")
		assert.False(t, isWitnessBurned(t, authWitness), "expected unused witness to remain unburned")
	})

	t.Run("AuthorizeWithWitness", func(t *testing.T) {
		restrictions := keychain.NewKeyRestrictions(^uint64(0))
		call, err := keychain.AuthorizeKeyWithWitness(accessKey.Address(), keychain.SignatureTypeSecp256k1, restrictions, authWitness)
		require.NoError(t, err)

		sendKeychainCall(t, call, "authorizeKey with witness failed")

		resultBytes := tc.callGetKey(rootAccount.Address(), accessKey.Address())
		recoveredKeyId := parseKeyInfoKeyId(resultBytes)
		assert.Equal(t, accessKey.Address(), recoveredKeyId, "getKey returned wrong keyId")
	})
}

// TestIntegration_T6KeyAuthorization tests tx-embedded key authorizations (TIP-1049).
// A root key authorizes another key inside a transaction, instead of via a
// separate AccountKeychain precompile call.
func TestIntegration_T6KeyAuthorization(t *testing.T) {
	if !isT6OrLater() {
		t.Skip("requires TEMPO_HARDFORK=T6 and a T6-capable RPC")
	}

	tc := newTestContext(t)
	rootAccount := tc.createAndFundSigner()
	t.Logf("Root account: %s", rootAccount.Address().Hex())

	// authorizeViaTx attaches a signed key authorization to a transaction and
	// sends it, signed by the root key. The authorization must be attached
	// before the transaction is signed.
	authorizeViaTx := func(t *testing.T, auth *keychain.KeyAuthorization, msg string) {
		t.Helper()
		tx := tc.newTxBuilder().
			SetNonce(tc.getNonce(rootAccount.Address())).
			SetGas(600000).
			AddCall(counterContract, big.NewInt(0), incrementSelector).
			Build()

		require.NoError(t, auth.SignAndAttach(tx, rootAccount))
		require.NoError(t, transaction.SignTransaction(tx, rootAccount))

		tc.sendTxExpectSuccess(tx, msg)
		time.Sleep(3 * time.Second)
	}

	t.Run("RootAuthorizesAccessKey", func(t *testing.T) {
		accessKeyPriv, err := crypto.GenerateKey()
		require.NoError(t, err)
		accessKey := signer.NewSignerFromKey(accessKeyPriv)

		auth := keychain.NewKeyAuthorization(uint64(tc.chainID), keychain.SignatureTypeSecp256k1, accessKey.Address())
		authorizeViaTx(t, auth, "tx-embedded key authorization failed")

		resultBytes := tc.callGetKey(rootAccount.Address(), accessKey.Address())
		assert.Equal(t, accessKey.Address(), parseKeyInfoKeyId(resultBytes),
			"key not authorized via tx-embedded authorization")
	})

	t.Run("RootAuthorizesAdminKey", func(t *testing.T) {
		adminKeyPriv, err := crypto.GenerateKey()
		require.NoError(t, err)
		adminKey := signer.NewSignerFromKey(adminKeyPriv)

		// Root-signed admin authorization, bound to the root account.
		auth := keychain.NewKeyAuthorization(uint64(tc.chainID), keychain.SignatureTypeSecp256k1, adminKey.Address()).
			IntoAdmin(rootAccount.Address())
		authorizeViaTx(t, auth, "tx-embedded admin key authorization failed")

		resultBytes := tc.callGetKey(rootAccount.Address(), adminKey.Address())
		assert.Equal(t, adminKey.Address(), parseKeyInfoKeyId(resultBytes),
			"admin key not authorized via tx-embedded authorization")
	})
}

// TestIntegration_KeychainWithLimits tests authorizeKey with enforceLimits=true and a non-empty TokenLimit[]
func TestIntegration_KeychainWithLimits(t *testing.T) {
	tc := newTestContext(t)

	rootAccount := tc.createAndFundSigner()
	accessKeyPriv, err := crypto.GenerateKey()
	require.NoError(t, err)
	accessKey := signer.NewSignerFromKey(accessKeyPriv)

	expiry := farFutureKeyExpiry
	limitAmount := new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18)) // 1000 tokens

	t.Logf("Root account: %s", rootAccount.Address().Hex())
	t.Logf("Access key: %s", accessKey.Address().Hex())

	// Authorize with enforceLimits=true and one TokenLimit for nativeFeeToken
	// ABI layout for dynamic array:
	//   head: keyId (32) | sigType (32) | expiry (32) | enforceLimits (32) | offset (32)
	//   tail: length (32) | element[0].token (32) | element[0].amount (32)
	authCalldata := encodeCalldata(
		authorizeKeySelector,
		addressToBytes32(accessKey.Address()),
		padLeft32([]byte{0}), // Secp256k1
		uint256ToBytes32(big.NewInt(expiry)),
		padLeft32([]byte{1}),               // enforceLimits = true
		uint256ToBytes32(big.NewInt(0xa0)), // offset to dynamic array (5 * 32 = 160 = 0xa0)
		uint256ToBytes32(big.NewInt(1)),    // array length = 1
		addressToBytes32(nativeFeeToken),   // limits[0].token
		uint256ToBytes32(limitAmount),      // limits[0].amount
	)

	authTx := tc.newTxBuilder().
		SetNonce(tc.getNonce(rootAccount.Address())).
		SetGas(600000).
		AddCall(accountKeychain, big.NewInt(0), authCalldata).
		Build()

	err = transaction.SignTransaction(authTx, rootAccount)
	require.NoError(t, err)

	receipt, _ := tc.sendTx(authTx)
	require.NotNil(t, receipt, "Failed to get receipt")
	status, _ := receipt["status"].(string)
	if status != "0x1" {
		t.Skip("authorizeKey with enforceLimits=true reverted on this network — precompile may not support spending limits yet")
	}
	tc.formatReceipt(receipt)

	time.Sleep(3 * time.Second)

	// Verify key was stored with enforceLimits=true
	resultBytes := tc.callGetKey(rootAccount.Address(), accessKey.Address())
	recoveredKeyId := parseKeyInfoKeyId(resultBytes)
	assert.Equal(t, accessKey.Address(), recoveredKeyId, "getKey returned wrong keyId")

	// enforceLimits is the 4th word (offset 96-128)
	enforceLimits := false
	for _, b := range resultBytes[96:128] {
		if b != 0 {
			enforceLimits = true
			break
		}
	}
	assert.True(t, enforceLimits, "expected enforceLimits to be true")

	// Verify spending limit via getRemainingLimit
	getRemainingCalldata := encodeCalldata(
		mustDecodeSelector(keychain.GetRemainingLimitSelector),
		addressToBytes32(rootAccount.Address()),
		addressToBytes32(accessKey.Address()),
		addressToBytes32(nativeFeeToken),
	)

	resp, err := tc.client.SendRequest(tc.ctx, "eth_call", map[string]interface{}{
		"to":   accountKeychain.Hex(),
		"data": "0x" + hex.EncodeToString(getRemainingCalldata),
	}, "latest")
	require.NoError(t, err)
	require.Nil(t, resp.Error, "getRemainingLimit eth_call failed: %v", resp.Error)

	result, ok := resp.Result.(string)
	require.True(t, ok, "expected string result from getRemainingLimit")

	remainingBytes, err := hex.DecodeString(strings.TrimPrefix(result, "0x"))
	require.NoError(t, err)
	remaining := new(big.Int).SetBytes(remainingBytes)
	assert.Equal(t, limitAmount, remaining, "remaining limit should match configured amount")

	t.Logf("getRemainingLimit returned: %s", remaining.String())
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

// buildAuthorizeKeyCalldata builds ABI-encoded calldata for authorizeKey,
// using the legacy flat-param ABI on pre-T3 and the KeyRestrictions struct on T3+.
func buildAuthorizeKeyCalldata(keyAddr common.Address, expiry int64, enforceLimits bool) []byte {
	enforceByte := byte(0)
	if enforceLimits {
		enforceByte = 1
	}

	if isT2() {
		return encodeCalldata(
			authorizeKeySelector,
			addressToBytes32(keyAddr),
			padLeft32([]byte{0}),
			uint256ToBytes32(big.NewInt(expiry)),
			padLeft32([]byte{enforceByte}),
			uint256ToBytes32(big.NewInt(0xa0)),
			uint256ToBytes32(big.NewInt(0)),
		)
	}

	// T3+: authorizeKey(address,uint8,KeyRestrictions)
	// KeyRestrictions = (uint64 expiry, bool enforceLimits, TokenLimit[] limits, bool allowAnyCalls, CallScope[] allowedCalls)
	sel := mustDecodeSelector(keychain.AuthorizeKeyT3Selector)
	return encodeCalldata(
		sel,
		addressToBytes32(keyAddr),
		padLeft32([]byte{0}),               // Secp256k1
		uint256ToBytes32(big.NewInt(0x60)), // offset to KeyRestrictions tuple
		// KeyRestrictions struct:
		uint256ToBytes32(big.NewInt(expiry)), // expiry
		padLeft32([]byte{enforceByte}),       // enforceLimits
		uint256ToBytes32(big.NewInt(0xa0)),   // offset to limits array (relative to struct start)
		padLeft32([]byte{1}),                 // allowAnyCalls = true
		uint256ToBytes32(big.NewInt(0xc0)),   // offset to allowedCalls array (relative to struct start)
		uint256ToBytes32(big.NewInt(0)),      // limits.length = 0
		uint256ToBytes32(big.NewInt(0)),      // allowedCalls.length = 0
	)
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
