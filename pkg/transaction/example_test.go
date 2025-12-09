package transaction_test

import (
	"context"
	"fmt"
	"log"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/tempoxyz/tempo-go/pkg/client"
	"github.com/tempoxyz/tempo-go/pkg/signer"
	"github.com/tempoxyz/tempo-go/pkg/transaction"
)

// Example_simpleTransaction demonstrates creating, signing, and sending a simple transaction.
func Example_simpleTransaction() {
	sgn, err := signer.NewSigner("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	if err != nil {
		log.Fatal(err)
	}

	tx := transaction.NewBuilder(big.NewInt(42424)).
		SetGas(100000).
		SetMaxFeePerGas(big.NewInt(1000000000)).
		SetMaxPriorityFeePerGas(big.NewInt(1000000)).
		AddCall(
			common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8"),
			big.NewInt(0),
			[]byte{},
		).
		Build()

	err = transaction.SignTransaction(tx, sgn)
	if err != nil {
		log.Fatal(err)
	}

	serialized, err := transaction.Serialize(tx, nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Transaction serialized: %s\n", serialized[:20]+"...")
}

// Example_feePayerTransaction demonstrates the fee payer pattern where a third party pays gas fees.
func Example_feePayerTransaction() {
	sender, _ := signer.NewSigner("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	feePayer, _ := signer.NewSigner("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d")

	tx := transaction.NewBuilder(big.NewInt(42424)).
		SetGas(100000).
		SetMaxFeePerGas(big.NewInt(1000000000)).
		AddCall(
			common.HexToAddress("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"),
			big.NewInt(0),
			[]byte{},
		).
		Build()

	transaction.SignTransaction(tx, sender)

	transaction.AddFeePayerSignature(tx, feePayer)

	recoveredSender, recoveredFeePayer, err := transaction.VerifyDualSignatures(tx)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Sender: %s, Fee Payer: %s\n",
		recoveredSender.Hex()[:10]+"...",
		recoveredFeePayer.Hex()[:10]+"...")

}

// Example_batchTransaction demonstrates creating a transaction with multiple calls.
func Example_batchTransaction() {
	tx := transaction.NewBuilder(big.NewInt(42424)).
		SetGas(200000).
		SetMaxFeePerGas(big.NewInt(1000000000)).
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

	fmt.Printf("Transaction has %d calls\n", len(tx.Calls))

}

// Example_clientUsage demonstrates using the RPC client.
func Example_clientUsage() {
	rpcClient := client.New("https://rpc.testnet.tempo.xyz")

	sgn, _ := signer.NewSigner("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	tx := transaction.NewBuilder(big.NewInt(42424)).
		SetGas(100000).
		SetMaxFeePerGas(big.NewInt(1000000000)).
		AddCall(
			common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8"),
			big.NewInt(0),
			[]byte{},
		).
		Build()

	transaction.SignTransaction(tx, sgn)
	serialized, _ := transaction.Serialize(tx, nil)

	// Send to network (would fail in this example without a real node)
	ctx := context.Background()
	_, err := rpcClient.SendRawTransaction(ctx, serialized)

	// In a real application, check for errors
	fmt.Printf("Would send transaction, got error: %v\n", err != nil)

	// Output:
	// Would send transaction, got error: true
}
