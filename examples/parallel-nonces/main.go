package main

import (
	"context"
	"log"
	"math/big"
	"os"
	"strconv"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/joho/godotenv"
	"github.com/tempoxyz/tempo-go/pkg/client"
	"github.com/tempoxyz/tempo-go/pkg/signer"
	"github.com/tempoxyz/tempo-go/pkg/transaction"
)

func init() {
	// Load .env file if present (errors ignored - env vars may be set directly)
	_ = godotenv.Load()
}

func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

func getEnvInt64(key string, defaultValue int64) int64 {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	intValue, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return defaultValue
	}
	return intValue
}

// Fixed nonce keys for parallel transaction lanes.
// These are reusable - once a transaction confirms, the same key can be reused.
const (
	NonceKey1 = 1
	NonceKey2 = 2
	NonceKey3 = 3
)

// This example demonstrates how to send multiple transactions in parallel using
// different nonce keys. Tempo's 2D nonce system allows each nonce key to have its
// own independent sequence, enabling true parallelism without waiting for confirmations.
func main() {
	rpcURL := getEnv("TEMPO_RPC_URL", "https://rpc.testnet.tempo.xyz")
	rpcUsername := getEnv("TEMPO_RPC_USERNAME", "")
	rpcPassword := getEnv("TEMPO_RPC_PASSWORD", "")
	privateKey := getEnv("TEMPO_PRIVATE_KEY", "")
	chainID := getEnvInt64("TEMPO_CHAIN_ID", 42429)
	recipientAddress := getEnv("TEMPO_RECIPIENT_ADDRESS", "")

	if privateKey == "" {
		log.Fatal("TEMPO_PRIVATE_KEY environment variable is required")
	}
	if recipientAddress == "" {
		log.Fatal("TEMPO_RECIPIENT_ADDRESS environment variable is required")
	}

	sgn, err := signer.NewSigner(privateKey)
	if err != nil {
		log.Fatalf("Failed to create signer: %v", err)
	}

	log.Printf("Sender address: %s", sgn.Address().Hex())

	var rpcClient *client.Client
	if rpcUsername != "" && rpcPassword != "" {
		rpcClient = client.New(rpcURL, client.WithAuth(rpcUsername, rpcPassword))
	} else {
		rpcClient = client.New(rpcURL)
	}

	ctx := context.Background()
	recipient := common.HexToAddress(recipientAddress)

	// Define which nonce keys to use for parallel sends.
	// These are fixed keys that can be reused once transactions confirm.
	nonceKeys := []*big.Int{big.NewInt(NonceKey1), big.NewInt(NonceKey2), big.NewInt(NonceKey3)}

	// Query the current nonce for each key in parallel.
	nonces := make(map[int64]uint64)
	var mu sync.Mutex
	var wg sync.WaitGroup

	log.Println("Fetching nonces for each key...")
	for _, key := range nonceKeys {
		wg.Add(1)
		go func(nonceKey *big.Int) {
			defer wg.Done()
			nonce, err := rpcClient.GetNonce(ctx, sgn.Address().Hex(), nonceKey)
			if err != nil {
				log.Printf("Failed to get nonce for key %d: %v", nonceKey.Int64(), err)
				return
			}
			mu.Lock()
			nonces[nonceKey.Int64()] = nonce
			mu.Unlock()
			log.Printf("Nonce for key %d: %d", nonceKey.Int64(), nonce)
		}(key)
	}
	wg.Wait()

	if len(nonces) != len(nonceKeys) {
		log.Fatal("Failed to fetch all nonces")
	}

	// Send transactions in parallel using different nonce keys.
	results := make(chan string, len(nonceKeys))
	errors := make(chan error, len(nonceKeys))

	log.Println("Sending transactions in parallel...")
	for _, nonceKey := range nonceKeys {
		wg.Add(1)
		go func(key *big.Int, nonce uint64) {
			defer wg.Done()

			tx := transaction.NewBuilder(big.NewInt(chainID)).
				SetNonceKey(key).
				SetNonce(nonce).
				SetGas(100000).
				SetMaxFeePerGas(big.NewInt(10000000000)).
				SetMaxPriorityFeePerGas(big.NewInt(1000000000)).
				AddCall(recipient, big.NewInt(0), []byte{}).
				Build()

			err := transaction.SignTransaction(tx, sgn)
			if err != nil {
				errors <- err
				return
			}

			serialized, err := transaction.Serialize(tx, nil)
			if err != nil {
				errors <- err
				return
			}

			txHash, err := rpcClient.SendRawTransaction(ctx, serialized)
			if err != nil {
				errors <- err
				return
			}

			results <- txHash
			log.Printf("Transaction with nonce key %d sent: %s", key.Int64(), txHash)
		}(nonceKey, nonces[nonceKey.Int64()])
	}

	wg.Wait()
	close(results)
	close(errors)

	// Collect results.
	var successCount int
	for hash := range results {
		log.Printf("Success: %s", hash)
		successCount++
	}

	for err := range errors {
		log.Printf("Error: %v", err)
	}

	log.Printf("Sent %d/%d transactions in parallel", successCount, len(nonceKeys))
}
