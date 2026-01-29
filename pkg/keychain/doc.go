// Package keychain provides access key management and signing for Tempo transactions.
//
// The AccountKeychain precompile manages authorized Access Keys for accounts,
// enabling Root Keys (e.g., passkeys) to provision scoped "secondary" Access Keys
// with expiry timestamps and per-TIP20 token spending limits.
//
// # Keychain Signature Format
//
// Per Tempo spec, Keychain signatures have format:
//
//	0x03 || root_account (20 bytes) || inner_signature (65 bytes)
//
// Where:
//   - 0x03 is the Keychain signature type identifier
//   - root_account is the account the access key signs on behalf of
//   - inner_signature is the secp256k1 signature from the access key (r || s || v)
//
// Total signature length: 86 bytes
//
// # Example Usage
//
//	// Create a transaction
//	tx := transaction.NewTx()
//	tx.ChainID = big.NewInt(42431)
//	tx.Calls = []transaction.Call{{To: &recipient, Value: big.NewInt(1000000)}}
//
//	// Sign with access key instead of root key
//	accessKeySigner, _ := signer.NewSigner(accessKeyPrivateKey)
//	err := keychain.SignWithAccessKey(tx, accessKeySigner, rootAccount)
//
// # AccountKeychain Precompile
//
// The precompile is located at address 0xAAAAAAAA00000000000000000000000000000000.
// It provides functions for:
//   - authorizeKey: Authorize a new access key with optional spending limits
//   - revokeKey: Revoke an access key
//   - updateSpendingLimit: Update spending limit for a token
//   - getRemainingLimit: Query remaining spending limit
package keychain
