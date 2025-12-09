package main

import (
	"context"
	"log"
	"math/big"
	"os"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/tempoxyz/tempo-go/pkg/client"
	"github.com/tempoxyz/tempo-go/pkg/signer"
	"github.com/tempoxyz/tempo-go/pkg/transaction"
)

// getEnv gets an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// getEnvInt64 gets an environment variable as int64 or returns a default value
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

// This example demonstrates how to create, sign, and send a simple Type 0x76 transaction.
func main() {
	// Configuration from environment variables
	rpcURL := getEnv("TEMPO_RPC_URL", "https://rpc.testnet.tempo.xyz")
	rpcUsername := getEnv("TEMPO_RPC_USERNAME", "")
	rpcPassword := getEnv("TEMPO_RPC_PASSWORD", "")
	privateKey := getEnv("TEMPO_PRIVATE_KEY", "")
	chainID := getEnvInt64("TEMPO_CHAIN_ID", 42429) // Default to Tempo testnet
	recipientAddress := getEnv("TEMPO_RECIPIENT_ADDRESS", "")

	// Validate required environment variables
	if privateKey == "" {
		log.Fatal("TEMPO_PRIVATE_KEY environment variable is required")
	}
	if recipientAddress == "" {
		log.Fatal("TEMPO_RECIPIENT_ADDRESS environment variable is required")
	}

	// Create signer from private key
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

	nonce, err := rpcClient.GetTransactionCount(ctx, sgn.Address().Hex())
	if err != nil {
		log.Fatalf("Failed to get nonce: %v", err)
	}

	// Create a new Type 0x76 transaction using the builder pattern
	tx := transaction.NewBuilder(big.NewInt(chainID)).
		SetNonce(nonce).
		SetGas(100000).
		SetMaxFeePerGas(big.NewInt(10000000000)).        // 10 gwei
		SetMaxPriorityFeePerGas(big.NewInt(1000000000)). // 1 gwei
		AddCall(
			common.HexToAddress(recipientAddress),
			big.NewInt(0),
			[]byte{}, // Empty data for simple transfer
		).
		Build()

	err = transaction.SignTransaction(tx, sgn)
	if err != nil {
		log.Fatalf("Failed to sign transaction: %v", err)
	}

	serialized, err := transaction.Serialize(tx, nil)
	if err != nil {
		log.Fatalf("Failed to serialize transaction: %v", err)
	}

	log.Printf("Serialized transaction: %s", serialized)

	// Send transaction to the network
	txHash, err := rpcClient.SendRawTransaction(ctx, serialized)
	if err != nil {
		log.Fatalf("Failed to send transaction: %v", err)
	}

	log.Printf("Transaction sent successfully! Hash: %s", txHash)
}
