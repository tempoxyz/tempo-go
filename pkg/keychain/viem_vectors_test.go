package keychain

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tempoxyz/tempo-go/pkg/signer"
	"github.com/tempoxyz/tempo-go/pkg/transaction"
)

type viemKeychainVectors struct {
	RPID            string         `json:"rpId"`
	Origin          string         `json:"origin"`
	P256Key         string         `json:"p256Key"`
	WebAuthnKey     string         `json:"webAuthnKey"`
	RootKey         string         `json:"rootKey"`
	RootAddress     common.Address `json:"rootAddress"`
	P256Address     common.Address `json:"p256Address"`
	WebAuthnAddress common.Address `json:"webAuthnAddress"`
	P256Auth        struct {
		Serialized hexutil.Bytes `json:"serialized"`
	} `json:"p256KeyAuthorization"`
	WebAuthnAuth struct {
		Serialized hexutil.Bytes `json:"serialized"`
	} `json:"webAuthnKeyAuthorization"`
	P256AccessKeyTx struct {
		Serialized string `json:"serialized"`
	} `json:"p256AccessKeyTransaction"`
}

func loadViemKeychainVectors(t *testing.T) (viemKeychainVectors, *signer.Signer, *signer.P256Signer, *signer.WebAuthnSigner) {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/viem/vectors.json")
	require.NoError(t, err)
	var v viemKeychainVectors
	require.NoError(t, json.Unmarshal(raw, &v))
	root, err := signer.NewSigner(v.RootKey)
	require.NoError(t, err)
	p256, err := signer.NewP256Signer(v.P256Key)
	require.NoError(t, err)
	webAuthn, err := signer.NewWebAuthnSigner(v.WebAuthnKey, v.RPID, v.Origin)
	require.NoError(t, err)
	return v, root, p256, webAuthn
}

// A root key authorizes P256 and WebAuthn access keys exactly as viem's
// Account.signKeyAuthorization does.
func TestViem_KeyAuthorizationForP256AndWebAuthnKeys(t *testing.T) {
	v, root, p256, webAuthn := loadViemKeychainVectors(t)
	for name, tt := range map[string]struct {
		key  signer.EnvelopeSigner
		want []byte
	}{
		"p256":     {p256, v.P256Auth.Serialized},
		"webauthn": {webAuthn, v.WebAuthnAuth.Serialized},
	} {
		t.Run(name, func(t *testing.T) {
			signed, err := NewKeyAuthorizationFor(42431, tt.key).WithExpiry(4102444800).SignWith(root)
			require.NoError(t, err)
			encoded, err := rlp.EncodeToBytes(signed)
			require.NoError(t, err)
			assert.Equal(t, hexutil.Encode(tt.want), hexutil.Encode(encoded))
		})
	}
}

// A P256 or WebAuthn root key can sign a key authorization; it verifies as
// that root's account.
func TestKeyAuthorization_SignWithP256Root(t *testing.T) {
	_, root, p256, webAuthn := loadViemKeychainVectors(t)
	for name, s := range map[string]signer.EnvelopeSigner{"p256": p256, "webauthn": webAuthn} {
		t.Run(name, func(t *testing.T) {
			auth := NewKeyAuthorizationFor(42431, root)
			signed, err := auth.SignWith(s)
			require.NoError(t, err)
			hash, err := auth.SignatureHash()
			require.NoError(t, err)
			recovered, err := signer.RecoverEnvelope(hash, signed[1].([]byte))
			require.NoError(t, err)
			assert.Equal(t, s.Address(), recovered.Account)
		})
	}
}

// A P256 access key signs a transaction for its root account byte for byte
// as viem, and VerifyAccessKeySignature recovers both.
func TestViem_SignWithP256AccessKey(t *testing.T) {
	v, _, p256, _ := loadViemKeychainVectors(t)
	tx, err := transaction.Deserialize(v.P256AccessKeyTx.Serialized)
	require.NoError(t, err)

	keyID, account, err := VerifyAccessKeySignature(tx)
	require.NoError(t, err)
	assert.Equal(t, v.P256Address, keyID)
	assert.Equal(t, v.RootAddress, account)

	resigned := tx.Clone()
	resigned.Signature = nil
	require.NoError(t, SignWithAccessKeyEnvelope(resigned, p256, v.RootAddress))
	serialized, err := transaction.Serialize(resigned, nil)
	require.NoError(t, err)
	assert.Equal(t, v.P256AccessKeyTx.Serialized, serialized)
}

// Secp256k1, P256 and WebAuthn access keys round-trip through
// SignWithAccessKeyEnvelope and VerifyAccessKeySignature; the secp256k1
// envelope is the same 86 bytes SignWithAccessKey produces.
func TestSignWithAccessKeyEnvelope_AllKeyTypes(t *testing.T) {
	v, root, p256, webAuthn := loadViemKeychainVectors(t)
	accessKey, err := signer.NewSigner("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d")
	require.NoError(t, err)
	base, err := transaction.Deserialize(v.P256AccessKeyTx.Serialized)
	require.NoError(t, err)
	base.Signature = nil

	for name, key := range map[string]signer.EnvelopeSigner{"secp256k1": accessKey, "p256": p256, "webauthn": webAuthn} {
		t.Run(name, func(t *testing.T) {
			tx := base.Clone()
			require.NoError(t, SignWithAccessKeyEnvelope(tx, key, root.Address()))
			keyID, account, err := VerifyAccessKeySignature(tx)
			require.NoError(t, err)
			assert.Equal(t, key.Address(), keyID)
			assert.Equal(t, root.Address(), account)

			serialized, err := transaction.Serialize(tx, nil)
			require.NoError(t, err)
			decoded, err := transaction.Deserialize(serialized)
			require.NoError(t, err)
			assert.Equal(t, tx.Signature.Raw, decoded.Signature.Raw)
		})
	}

	legacy := base.Clone()
	require.NoError(t, SignWithAccessKey(legacy, accessKey, root.Address()))
	generic := base.Clone()
	require.NoError(t, SignWithAccessKeyEnvelope(generic, accessKey, root.Address()))
	assert.Equal(t, legacy.Signature.Raw, generic.Signature.Raw)
}

func TestVerifyAccessKeySignature_RejectsPrimitiveSignatures(t *testing.T) {
	v, _, p256, _ := loadViemKeychainVectors(t)
	tx, err := transaction.Deserialize(v.P256AccessKeyTx.Serialized)
	require.NoError(t, err)
	tx.Signature = nil
	require.NoError(t, transaction.SignTransactionWith(tx, p256))
	tx.Signature.Type = "keychain"
	_, _, err = VerifyAccessKeySignature(tx)
	assert.Error(t, err)
}
