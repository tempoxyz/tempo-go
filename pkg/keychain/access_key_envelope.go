package keychain

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/tempoxyz/tempo-go/pkg/signer"
	"github.com/tempoxyz/tempo-go/pkg/transaction"
)

// SignWithAccessKeyEnvelope signs a Tempo transaction for rootAccount with an
// access key of any type (secp256k1, P256 or WebAuthn), as a Keychain V2
// envelope: 0x04 || rootAccount || inner, the inner signature over
// keccak256(0x04 || sig_hash || rootAccount), as viem's access-key accounts
// sign.
func SignWithAccessKeyEnvelope(tx *transaction.Tx, accessKey signer.EnvelopeSigner, rootAccount common.Address) error {
	if err := tx.Validate(); err != nil {
		return err
	}
	tx.From = rootAccount
	sigHash, err := transaction.GetSignPayload(tx)
	if err != nil {
		return fmt.Errorf("failed to get sign payload: %w", err)
	}
	inner, err := accessKey.SignEnvelope(signer.KeychainV2Hash(sigHash, rootAccount))
	if err != nil {
		return fmt.Errorf("failed to sign with access key: %w", err)
	}
	envelope, err := signer.BuildKeychainEnvelope(signer.SignatureTypeKeychainV2, rootAccount, inner)
	if err != nil {
		return err
	}
	tx.Signature = &signer.SignatureEnvelope{Type: "keychain", Raw: envelope}
	return nil
}

// SignWith signs the authorization with a root (or admin) key of any type
// and returns the signed key authorization value to assign to
// tx.KeyAuthorization.
func (a *KeyAuthorization) SignWith(s signer.EnvelopeSigner) ([]interface{}, error) {
	if secp, ok := s.(*signer.Signer); ok {
		return a.Sign(secp)
	}
	hash, err := a.SignatureHash()
	if err != nil {
		return nil, err
	}
	signature, err := s.SignEnvelope(hash)
	if err != nil {
		return nil, fmt.Errorf("failed to sign key authorization: %w", err)
	}
	return a.BuildSigned(signature)
}

// NewKeyAuthorizationFor authorizes accessKey on chainID: its key type and
// address (for P256 and WebAuthn keys, the address of the public key).
func NewKeyAuthorizationFor(chainID uint64, accessKey signer.EnvelopeSigner) *KeyAuthorization {
	return NewKeyAuthorization(chainID, accessKey.KeyType(), accessKey.Address())
}
