// Package client provides an HTTP RPC client for interacting with the Tempo blockchain.
//
// This package implements a JSON-RPC 2.0 client for sending transactions and querying
// the Tempo network.
//
// # Basic Usage
//
// Create a client and send a transaction:
//
//	client := client.New(
//		"https://rpc.moderato.tempo.xyz",
//		client.WithAuth("username", "password"), // optional basic auth
//	)
//
//	// Send a transaction asynchronously
//	txHash, err := client.SendRawTransaction(context.Background(), "0x76...")
//	if err != nil {
//		log.Fatal(err)
//	}
//	fmt.Printf("Transaction hash: %s\n", txHash)
//
// Synchronous transaction broadcasting:
//
//	// Wait for transaction to be included in a block
//	txHash, err := client.SendRawTransactionSync(context.Background(), "0x76...")
//	if err != nil {
//		log.Fatal(err)
//	}
//	fmt.Printf("Transaction confirmed: %s\n", txHash)
//
// Sign a transaction without broadcasting:
//
//	// Sign transaction and get the raw hex without broadcasting
//	signedTx, err := client.SignTransaction(context.Background(), txObject)
//	if err != nil {
//		log.Fatal(err)
//	}
//	// Now you can broadcast it yourself or through a different channel
//	fmt.Printf("Signed transaction: %s\n", signedTx)
//
// Generic RPC requests:
//
//	// Call any JSON-RPC method
//	response, err := client.SendRequest(context.Background(), "eth_blockNumber")
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	if response.Error != nil {
//		log.Fatalf("RPC error: %s", response.Error.Message)
//	}
//
//	blockNum := response.Result.(string)
//	fmt.Printf("Block number: %s\n", blockNum)
package client
