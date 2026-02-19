// Package transaction provides types and functions for working with Tempo Transactions.
//
// TempoTransactions are Tempo's native account abstraction transaction type that support:
//   - Batched calls: Execute multiple contract calls in a single transaction
//   - 2D nonce system: Use sequence keys (nonceKey) for parallel transaction processing
//   - Fee abstraction: Pay gas fees in stablecoins (e.g., AlphaUSD) instead of native tokens
//   - Fee payer pattern: Allow third-party fee payers to sponsor transaction gas costs
//   - Time-based validity: Set activation (validAfter) and expiration (validBefore) times
//
// # Basic Usage
//
// Create and serialize a transaction:
//
//	tx := transaction.New()
//	tx.Gas = 100000
//	tx.AddCall(common.HexToAddress("0x..."), big.NewInt(0), []byte{})
//
//	// Sign the transaction
//	signer, _ := signer.NewSigner("0x...")
//	transaction.SignTransaction(tx, signer)
//
//	// Serialize to hex string
//	serialized, _ := transaction.Serialize(tx, nil)
//	// Returns: "0x76..." (ready to broadcast)
//
// Deserialize a transaction:
//
//	tx, err := transaction.Deserialize("0x76...")
//	if err != nil {
//		log.Fatal(err)
//	}
//
// # Fee Payer Pattern
//
// The fee payer pattern allows a third party to pay gas fees:
//
//	// 1. User signs their transaction
//	userTx := transaction.New()
//	// ... configure transaction ...
//	transaction.SignTransaction(userTx, userSigner)
//
//	// 2. Fee payer adds their signature
//	transaction.AddFeePayerSignature(userTx, feePayerSigner)
//
//	// 3. Broadcast dual-signed transaction
//	serialized, _ := transaction.Serialize(userTx, nil)
//	// Broadcast to network...
//
// 2D Nonce System
//
// Use nonceKey to enable parallel transactions:
//
//	// Transaction 1 with sequence A
//	tx1 := transaction.New()
//	tx1.NonceKey = big.NewInt(1) // Sequence A
//	tx1.Nonce = 0                 // First in sequence
//
//	// Transaction 2 with sequence B (can be processed in parallel)
//	tx2 := transaction.New()
//	tx2.NonceKey = big.NewInt(2) // Sequence B
//	tx2.Nonce = 0                 // First in sequence
//
// # Time-Based Validity
//
// Set transaction validity windows:
//
//	tx := transaction.New()
//	tx.ValidAfter = uint64(time.Now().Unix())             // Activate now
//	tx.ValidBefore = uint64(time.Now().Add(1 * time.Hour).Unix()) // Expire in 1 hour
//
// For more details on the TempoTransaction specification, see the Tempo documentation.
package transaction
