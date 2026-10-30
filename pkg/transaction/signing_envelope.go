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
	switch s.KeyType() {
	case signer.KeyTypeSecp256k1:
		// Any secp256k1 signer (a KMS or hardware wrapper): a parsed
		// signature, as SignTransaction sets.
		decoded, err := decodeSignatureEnvelope(envelope)
		if err != nil || decoded.Type != SignatureTypeSecp256k1 {
			return fmt.Errorf("secp256k1 signer returned an invalid signature")
		}
		tx.Signature = decoded
	case signer.KeyTypeP256, signer.KeyTypeWebAuthn:
		signatureType := SignatureTypeP256
		if s.KeyType() == signer.KeyTypeWebAuthn {
			signatureType = SignatureTypeWebAuthn
		}
		if err := signer.ValidatePrimitive(envelope); err != nil || envelope[0] == 0 {
			return fmt.Errorf("%s signer returned an invalid signature: %v", signatureType, err)
		}
		tx.Signature = &signer.SignatureEnvelope{Type: signatureType, Raw: envelope}
	default:
		return fmt.Errorf("%w: key type %d", ErrUnsupportedSignatureType, s.KeyType())
	}
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
