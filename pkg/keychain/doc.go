// Package keychain provides access key management and signing for Tempo transactions.
//
// The AccountKeychain precompile manages authorized Access Keys for accounts,
// enabling Root Keys (e.g., passkeys) to provision scoped "secondary" Access Keys
// with expiry timestamps, per-TIP20 token spending limits, and call scope
// restrictions (per-contract, per-selector, and per-recipient filtering).
//
// # Keychain V2 Signature Format
//
// Per Tempo spec, Keychain V2 signatures have format:
//
//	0x04 || root_account (20 bytes) || inner_signature (65 bytes)
//
// Where:
//   - 0x04 is the Keychain V2 signature type identifier
//   - root_account is the account the access key signs on behalf of
//   - inner_signature is the secp256k1 signature from the access key (r || s || v)
//
// The access key signs keccak256(0x04 || sig_hash || user_address) instead of
// the raw sig_hash. The 0x04 domain separator prevents cross-scheme signature
// confusion.
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
// # Call Scope Restrictions
//
// Access keys can be scoped to specific contracts, function selectors, and
// recipients using [CallScope] and [SelectorRule]. Use [CallScopeBuilder] to
// construct scopes:
//
//	token := common.HexToAddress("0x20c0000000000000000000000000000000000001")
//	scope := keychain.NewCallScopeBuilder(token).
//		Transfer([]common.Address{recipient}).
//		Approve(nil).
//		Build()
//
//	restrictions := keychain.NewKeyRestrictions(expiry).
//		WithAllowedCalls([]keychain.CallScope{scope})
//
//	call, _ := keychain.AuthorizeKey(keyID, keychain.SignatureTypeSecp256k1, restrictions)
//
// # AccountKeychain Precompile
//
// The precompile is located at address 0xAAAAAAAA00000000000000000000000000000000.
// It provides functions for:
//   - authorizeKey: Authorize a new access key with restrictions
//   - revokeKey: Revoke an access key
//   - updateSpendingLimit: Update spending limit for a token
//   - setAllowedCalls: Set or replace call scope restrictions for a key
//   - removeAllowedCalls: Remove call scope rules for a key+target pair
//   - getRemainingLimit: Query remaining spending limit
package keychain
