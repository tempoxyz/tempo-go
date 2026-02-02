package transaction

import "errors"

// Sentinel errors for common error conditions.
// Use errors.Is() to check for specific error types.
var (
	// ErrNoSignature is returned when a transaction has no sender signature.
	ErrNoSignature = errors.New("transaction has no signature")

	// ErrNoFeePayerSignature is returned when a transaction has no fee payer signature.
	ErrNoFeePayerSignature = errors.New("transaction has no fee payer signature")

	// ErrMissingSenderSignature is returned when attempting to add a fee payer signature
	// to a transaction that doesn't have a sender signature yet.
	ErrMissingSenderSignature = errors.New("transaction must have sender signature before adding fee payer signature")

	// ErrInvalidTransaction is returned when a transaction cannot be parsed or is malformed.
	ErrInvalidTransaction = errors.New("invalid transaction")

	// ErrInvalidTransactionType is returned when a transaction has an unexpected type prefix.
	ErrInvalidTransactionType = errors.New("invalid transaction type")

	// ErrUnsupportedSignatureType is returned when attempting to verify a signature type
	// that cannot be verified via ecrecover (e.g., P256, WebAuthn, Keychain).
	ErrUnsupportedSignatureType = errors.New("unsupported signature type for verification")

	// ErrInvalidSignatureType is returned when a signature type is not allowed for the operation.
	// For example, fee payer signatures must be secp256k1.
	ErrInvalidSignatureType = errors.New("invalid signature type")
)
