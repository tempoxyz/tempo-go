package transaction

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tempoxyz/tempo-go/pkg/signer"
)

// ComputeHash computes the Keccak256 hash of a serialized transaction.
// This is useful for verifying transaction hashes or implementing custom signing logic.
func ComputeHash(serialized string) (common.Hash, error) {
	serializedBytes, err := common.ParseHexOrString(serialized)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to parse serialized transaction: %w", err)
	}
	return crypto.Keccak256Hash(serializedBytes), nil
}

// GetSignPayload computes the hash that the sender should sign.
func GetSignPayload(tx *Tx) (common.Hash, error) {
	serialized, err := SerializeForSigning(tx)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to serialize for signing: %w", err)
	}
	return ComputeHash(serialized)
}

// GetFeePayerSignPayload computes the hash that the fee payer should sign.
// This uses a different serialization format (0x78 prefix) and includes the sender address.
func GetFeePayerSignPayload(tx *Tx, sender common.Address) (common.Hash, error) {
	serialized, err := SerializeForFeePayerSigning(tx, sender)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to serialize for fee payer signing: %w", err)
	}
	return ComputeHash(serialized)
}

// SignTransaction signs a transaction with the sender's private key.
// This creates the sender signature envelope and adds it to the transaction.
func SignTransaction(tx *Tx, sgn *signer.Signer) error {
	// Validate transaction before signing
	if err := tx.Validate(); err != nil {
		return err
	}

	// Get the sign payload
	hash, err := GetSignPayload(tx)
	if err != nil {
		return fmt.Errorf("failed to get sign payload: %w", err)
	}

	// Sign the hash
	sig, err := sgn.Sign(hash)
	if err != nil {
		return fmt.Errorf("failed to sign transaction: %w", err)
	}

	// Create signature envelope (secp256k1 type)
	tx.Signature = signer.NewSignatureEnvelope(sig.R, sig.S, sig.YParity)
	tx.From = sgn.Address()

	return nil
}

// AddFeePayerSignature adds the fee payer signature to a transaction.
// The transaction must already have a sender signature.
func AddFeePayerSignature(tx *Tx, sgn *signer.Signer) error {
	// Ensure the transaction has a sender signature
	if tx.Signature == nil {
		return ErrMissingSenderSignature
	}

	// Recover sender address from signature if not set
	sender := tx.From
	if sender == (common.Address{}) {
		// Recover from the signature (secp256k1, P256 or WebAuthn). A
		// Keychain envelope names its account but proves nothing about the
		// key's authorization, so its sender must be set explicitly.
		if tx.Signature.Type == "keychain" {
			return fmt.Errorf("failed to recover sender address: set tx.From for a keychain signature")
		}
		recoveredSender, err := VerifySignature(tx)
		if err != nil {
			return fmt.Errorf("failed to recover sender address: %w", err)
		}
		sender = recoveredSender
		tx.From = sender
	}

	hash, err := GetFeePayerSignPayload(tx, sender)
	if err != nil {
		return fmt.Errorf("failed to get fee payer sign payload: %w", err)
	}

	sig, err := sgn.Sign(hash)
	if err != nil {
		return fmt.Errorf("failed to sign as fee payer: %w", err)
	}

	tx.FeePayerSignature = sig

	return nil
}

// VerifySignature verifies the sender signature on a transaction and returns
// the sender: the recovered secp256k1 address, or the address of the public
// key of a P256 or WebAuthn signature. Keychain (access key) signatures are
// rejected with ErrUnsupportedSignatureType: verify them with RecoverSigner or
// keychain.VerifyAccessKeySignature, then check the key's authorization on
// chain.
func VerifySignature(tx *Tx) (common.Address, error) {
	if tx.Signature == nil {
		return common.Address{}, ErrNoSignature
	}

	if tx.Signature.Type == SignatureTypeP256 || tx.Signature.Type == SignatureTypeWebAuthn {
		if tx.Signature.Raw == nil {
			return common.Address{}, fmt.Errorf("%s signature envelope has no raw bytes", tx.Signature.Type)
		}
		wantPrefix := signer.SignatureTypeP256
		if tx.Signature.Type == SignatureTypeWebAuthn {
			wantPrefix = signer.SignatureTypeWebAuthn
		}
		// RecoverSigner dispatches on the raw bytes: a Keychain envelope
		// labelled p256 or webauthn must not pass as a primitive sender.
		if len(tx.Signature.Raw) == 0 || tx.Signature.Raw[0] != wantPrefix {
			return common.Address{}, fmt.Errorf("%w: %s envelope does not hold a %s signature",
				ErrUnsupportedSignatureType, tx.Signature.Type, tx.Signature.Type)
		}
		recovered, err := RecoverSigner(tx)
		if err != nil {
			return common.Address{}, fmt.Errorf("failed to verify %s signature: %w", tx.Signature.Type, err)
		}
		if recovered.Keychain != 0 {
			return common.Address{}, fmt.Errorf("%w: keychain", ErrUnsupportedSignatureType)
		}
		return recovered.Account, nil
	}

	if tx.Signature.Type != "" && tx.Signature.Type != SignatureTypeSecp256k1 {
		return common.Address{}, fmt.Errorf("%w: %s (verify with RecoverSigner)",
			ErrUnsupportedSignatureType, tx.Signature.Type)
	}

	if tx.Signature.Signature == nil {
		return common.Address{}, fmt.Errorf("signature envelope has no parsed signature")
	}

	hash, err := GetSignPayload(tx)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to get sign payload: %w", err)
	}

	address, err := signer.RecoverAddress(hash, tx.Signature.Signature)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to recover address: %w", err)
	}

	return address, nil
}

// VerifyFeePayerSignature verifies the fee payer signature on a transaction.
// Per Tempo Transaction spec, fee payer signatures MUST be secp256k1.
// This is enforced by the type system: FeePayerSignature is *signer.Signature (not SignatureEnvelope).
func VerifyFeePayerSignature(tx *Tx, sender common.Address) (common.Address, error) {
	if tx.FeePayerSignature == nil {
		return common.Address{}, ErrNoFeePayerSignature
	}

	hash, err := GetFeePayerSignPayload(tx, sender)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to get fee payer sign payload: %w", err)
	}

	address, err := signer.RecoverAddress(hash, tx.FeePayerSignature)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to recover fee payer address: %w", err)
	}

	return address, nil
}

// VerifyDualSignatures verifies both sender and fee payer signatures.
// Returns sender address, fee payer address, and any error.
func VerifyDualSignatures(tx *Tx) (sender, feePayer common.Address, err error) {
	sender, err = VerifySignature(tx)
	if err != nil {
		return common.Address{}, common.Address{}, fmt.Errorf("sender signature verification failed: %w", err)
	}

	feePayer, err = VerifyFeePayerSignature(tx, sender)
	if err != nil {
		return common.Address{}, common.Address{}, fmt.Errorf("fee payer signature verification failed: %w", err)
	}

	return sender, feePayer, nil
}
