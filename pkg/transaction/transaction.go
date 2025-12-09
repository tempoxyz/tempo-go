package transaction

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/tempoxyz/tempo-go/pkg/signer"
)

// Tx represents a Tempo Transaction
type Tx struct {
	// Core transaction fields
	ChainID              *big.Int       `json:"chainId"`
	MaxPriorityFeePerGas *big.Int       `json:"maxPriorityFeePerGas"`
	MaxFeePerGas         *big.Int       `json:"maxFeePerGas"`
	Gas                  uint64         `json:"gas"`
	Calls                []Call         `json:"calls"`
	AccessList           AccessList     `json:"accessList"`
	NonceKey             *big.Int       `json:"nonceKey"`    // 192-bit sequence key for 2D nonce system
	Nonce                uint64         `json:"nonce"`       // Current value of the sequence key
	ValidBefore          uint64         `json:"validBefore"` // Optional expiration timestamp
	ValidAfter           uint64         `json:"validAfter"`  // Optional activation timestamp
	FeeToken             common.Address `json:"feeToken"`    // Stablecoin address for fees (e.g., AlphaUSD)

	// Signatures
	Signature         *signer.SignatureEnvelope `json:"signature"`         // Sender signature
	FeePayerSignature *signer.Signature         `json:"feePayerSignature"` // Fee payer signature (nil if not signed)

	// AwaitingFeePayer indicates the transaction was marked for fee payer sponsorship.
	// When true, serialization uses 0x00 marker
	// This is set when deserializing a transaction with feePayerSignature=null marker.
	AwaitingFeePayer bool `json:"-"`

	From common.Address `json:"from,omitempty"` // Sender address (recovered from signature)
}

// Call represents a single call within a TempoTransaction.
// Transactions can batch multiple calls together.
type Call struct {
	To    *common.Address `json:"to"`    // Target address (nil for contract creation)
	Value *big.Int        `json:"value"` // Amount to send in wei
	Data  []byte          `json:"data"`  // Call data
}

// AccessList is an EIP-2930 access list.
type AccessList []AccessTuple

// AccessTuple represents a single entry in an access list.
type AccessTuple struct {
	Address     common.Address `json:"address"`
	StorageKeys []common.Hash  `json:"storageKeys"`
}

// Constants
const (
	// SignatureTypeSecp256k1 is the signature type for standard ECDSA signatures
	SignatureTypeSecp256k1 = "secp256k1"

	// SignatureTypeP256 is the signature type for P256 signatures
	SignatureTypeP256 = "p256"

	// SignatureTypeWebAuthn is the signature type for WebAuthn signatures
	SignatureTypeWebAuthn = "webauthn"

	// ChainIDTempo is the chain ID for Tempo mainnet.
	ChainIDTempo = 42424

	// ChainIDTempoTestnet is the chain ID for Tempo testnet.
	ChainIDTempoTestnet = 42429

	// DefaultNonceKey is the standard nonce key for sequential transactions.
	DefaultNonceKey = 0
)

// Common fee token addresses.
var (
	// AlphaUSDAddress is the address of the AlphaUSD stablecoin on Tempo.
	AlphaUSDAddress = common.HexToAddress("0x20c0000000000000000000000000000000000001")
)

// New creates a new TempoTransaction with default values.
func New() *Tx {
	return &Tx{
		ChainID:              big.NewInt(0),
		MaxPriorityFeePerGas: big.NewInt(0),
		MaxFeePerGas:         big.NewInt(0),
		NonceKey:             big.NewInt(0),
	}
}

// NewDefault creates a new transaction with default values for the given chain ID.
func NewDefault(chainID int64) *Tx {
	tx := New()
	tx.ChainID = big.NewInt(chainID)
	tx.NonceKey = big.NewInt(DefaultNonceKey)
	return tx
}

// HasFeePayerSignature returns true if the transaction has a fee payer signature.
func (tx *Tx) HasFeePayerSignature() bool {
	return tx.FeePayerSignature != nil
}

// IsExpired checks if the transaction has expired based on validBefore.
func (tx *Tx) IsExpired(currentTime uint64) bool {
	return tx.ValidBefore > 0 && currentTime >= tx.ValidBefore
}

// IsActive checks if the transaction is active based on validAfter.
func (tx *Tx) IsActive(currentTime uint64) bool {
	return tx.ValidAfter == 0 || currentTime >= tx.ValidAfter
}

// String returns a human-readable representation of the transaction.
// Implements the fmt.Stringer interface for better debugging output.
func (tx *Tx) String() string {
	fromAddr := "not recovered"
	if tx.From != (common.Address{}) {
		fromAddr = tx.From.Hex()
	}

	hasSig := "no"
	if tx.Signature != nil {
		hasSig = "yes"
	}

	hasFeePayerSig := "no"
	if tx.FeePayerSignature != nil {
		hasFeePayerSig = "yes"
	}

	return fmt.Sprintf("Transaction{ChainID: %s, Gas: %d, Calls: %d, From: %s, Signed: %s, FeePayerSigned: %s}",
		tx.ChainID, tx.Gas, len(tx.Calls), fromAddr, hasSig, hasFeePayerSig)
}

// Validate checks if the transaction is valid before signing/serializing.
// Returns an error if any required fields are missing or invalid.
func (tx *Tx) Validate() error {
	if tx.ChainID == nil || tx.ChainID.Sign() == 0 {
		return fmt.Errorf("%w: chain ID must be set", ErrInvalidTransaction)
	}

	if tx.Gas == 0 {
		return fmt.Errorf("%w: gas must be greater than 0", ErrInvalidTransaction)
	}

	if len(tx.Calls) == 0 {
		return fmt.Errorf("%w: transaction must have at least one call", ErrInvalidTransaction)
	}

	// Validate each call
	for i, call := range tx.Calls {
		if call.Value == nil {
			return fmt.Errorf("%w: call %d has nil value", ErrInvalidTransaction, i)
		}
	}

	if tx.NonceKey == nil {
		return fmt.Errorf("%w: nonce key must be set", ErrInvalidTransaction)
	}

	return nil
}

// Hash computes the hash of a fully signed transaction.
// This returns the transaction hash that would appear on-chain.
// The transaction must be signed before calling this method.
func (tx *Tx) Hash() (common.Hash, error) {
	if tx.Signature == nil {
		return common.Hash{}, ErrNoSignature
	}

	serialized, err := Serialize(tx, nil)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to serialize: %w", err)
	}

	return ComputeHash(serialized)
}

// Clone creates a deep copy of the transaction.
// This is useful when you want to create variations of a transaction without
// modifying the original. Note that signatures are intentionally NOT copied
// since they are tied to specific transaction state.
//
// Example usage:
//
//	template := transaction.NewDefault(42424)
//	template.SetGas(100000)
//
//	// Create variations for different recipients
//	tx1 := template.Clone()
//	tx1.Calls = []transaction.Call{{To: &recipient1, Value: amount1}}
//
//	tx2 := template.Clone()
//	tx2.Calls = []transaction.Call{{To: &recipient2, Value: amount2}}
func (tx *Tx) Clone() *Tx {
	clone := &Tx{
		ChainID:              new(big.Int).Set(tx.ChainID),
		MaxPriorityFeePerGas: new(big.Int).Set(tx.MaxPriorityFeePerGas),
		MaxFeePerGas:         new(big.Int).Set(tx.MaxFeePerGas),
		Gas:                  tx.Gas,
		NonceKey:             new(big.Int).Set(tx.NonceKey),
		Nonce:                tx.Nonce,
		ValidBefore:          tx.ValidBefore,
		ValidAfter:           tx.ValidAfter,
		FeeToken:             tx.FeeToken,
		From:                 tx.From,
	}

	// Deep copy calls
	clone.Calls = make([]Call, len(tx.Calls))
	for i, call := range tx.Calls {
		clone.Calls[i] = Call{
			Value: new(big.Int).Set(call.Value),
			Data:  append([]byte{}, call.Data...),
		}
		if call.To != nil {
			toAddr := *call.To
			clone.Calls[i].To = &toAddr
		}
	}

	// Deep copy access list
	clone.AccessList = make(AccessList, len(tx.AccessList))
	for i, entry := range tx.AccessList {
		clone.AccessList[i] = AccessTuple{
			Address:     entry.Address,
			StorageKeys: append([]common.Hash{}, entry.StorageKeys...),
		}
	}

	// Note: We intentionally don't copy signatures as they're tied to specific transaction state
	// Signature and FeePayerSignature remain nil in the clone

	return clone
}
