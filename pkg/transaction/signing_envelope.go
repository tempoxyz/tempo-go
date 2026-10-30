package transaction

import (
	"fmt"

	"github.com/tempoxyz/tempo-go/pkg/signer"
)

// SignTransactionWith signs a transaction with any envelope signer: a
// secp256k1 Signer, a P256Signer or a WebAuthnSigner. The sender is the
// signer's address.
func SignTransactionWith(tx *Tx, s signer.EnvelopeSigner) error {
	if secp, ok := s.(*signer.Signer); ok {
		return SignTransaction(tx, secp)
	}
	if err := tx.Validate(); err != nil {
		return err
	}
	hash, err := GetSignPayload(tx)
	if err != nil {
		return fmt.Errorf("failed to get sign payload: %w", err)
	}
	envelope, err := s.SignEnvelope(hash)
	if err != nil {
		return fmt.Errorf("failed to sign transaction: %w", err)
	}
	signatureType := SignatureTypeP256
	if s.KeyType() == signer.KeyTypeWebAuthn {
		signatureType = SignatureTypeWebAuthn
	}
	tx.Signature = &signer.SignatureEnvelope{Type: signatureType, Raw: envelope}
	tx.From = s.Address()
	return nil
}

// RecoverSigner verifies the sender signature of any type and returns its
// signer. For a Keychain signature, Account is the user address and KeyID the
// access key: whether the account authorized that key is on-chain state the
// caller must check (the AccountKeychain precompile).
func RecoverSigner(tx *Tx) (signer.RecoveredSigner, error) {
	if tx.Signature == nil {
		return signer.RecoveredSigner{}, ErrNoSignature
	}
	envelope, err := encodeSignatureEnvelope(tx.Signature)
	if err != nil {
		return signer.RecoveredSigner{}, err
	}
	unsigned := *tx
	unsigned.Signature = nil
	hash, err := GetSignPayload(&unsigned)
	if err != nil {
		return signer.RecoveredSigner{}, fmt.Errorf("failed to get sign payload: %w", err)
	}
	return signer.RecoverEnvelope(hash, envelope)
}
