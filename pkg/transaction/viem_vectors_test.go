package transaction

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tempoxyz/tempo-go/pkg/signer"
)

// viemTransaction is a 0x76 transaction viem's tempo Accounts signed
// (testdata/viem/gen.mjs).
type viemTransaction struct {
	SignPayload common.Hash    `json:"signPayload"`
	Signature   hexutil.Bytes  `json:"signature"`
	Serialized  string         `json:"serialized"`
	Sender      common.Address `json:"sender"`
}

type viemTransactionVectors struct {
	RPID          string          `json:"rpId"`
	Origin        string          `json:"origin"`
	P256Key       string          `json:"p256Key"`
	WebAuthnKey   string          `json:"webAuthnKey"`
	RootAddress   common.Address  `json:"rootAddress"`
	P256Address   common.Address  `json:"p256Address"`
	P256Root      viemTransaction `json:"p256RootTransaction"`
	WebAuthnRoot  viemTransaction `json:"webAuthnRootTransaction"`
	P256AccessKey viemTransaction `json:"p256AccessKeyTransaction"`
}

func loadViemTransactions(t *testing.T) viemTransactionVectors {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/viem/vectors.json")
	require.NoError(t, err)
	var v viemTransactionVectors
	require.NoError(t, json.Unmarshal(raw, &v))
	return v
}

// P256 and WebAuthn root accounts sign transactions byte for byte as viem.
func TestViem_P256AndWebAuthnTransactions(t *testing.T) {
	v := loadViemTransactions(t)
	p256, err := signer.NewP256Signer(v.P256Key)
	require.NoError(t, err)
	webAuthn, err := signer.NewWebAuthnSigner(v.WebAuthnKey, v.RPID, v.Origin)
	require.NoError(t, err)

	for name, tt := range map[string]struct {
		vector  viemTransaction
		signer  signer.EnvelopeSigner
		sigType string
	}{
		"p256":     {v.P256Root, p256, SignatureTypeP256},
		"webauthn": {v.WebAuthnRoot, webAuthn, SignatureTypeWebAuthn},
	} {
		t.Run(name, func(t *testing.T) {
			tx, err := Deserialize(tt.vector.Serialized)
			require.NoError(t, err)
			require.NotNil(t, tx.Signature)
			assert.Equal(t, tt.sigType, tx.Signature.Type)
			assert.Equal(t, []byte(tt.vector.Signature), tx.Signature.Raw)

			sender, err := VerifySignature(tx)
			require.NoError(t, err)
			assert.Equal(t, tt.vector.Sender, sender)
			recovered, err := RecoverSigner(tx)
			require.NoError(t, err)
			assert.Equal(t, tt.vector.Sender, recovered.Account)

			unsigned := tx.Clone()
			unsigned.Signature = nil
			payload, err := GetSignPayload(unsigned)
			require.NoError(t, err)
			assert.Equal(t, tt.vector.SignPayload, payload)

			require.NoError(t, SignTransactionWith(unsigned, tt.signer))
			serialized, err := Serialize(unsigned, nil)
			require.NoError(t, err)
			assert.Equal(t, tt.vector.Serialized, serialized)
			assert.Equal(t, tt.vector.Sender, unsigned.From)
		})
	}
}

// Keychain envelopes of any length and inner type decode and re-encode
// unchanged; VerifySignature still leaves them to RecoverSigner.
func TestViem_KeychainTransactionDecodes(t *testing.T) {
	v := loadViemTransactions(t)
	tx, err := Deserialize(v.P256AccessKey.Serialized)
	require.NoError(t, err)
	assert.Equal(t, "keychain", tx.Signature.Type)
	assert.Len(t, tx.Signature.Raw, 1+20+130)

	recovered, err := RecoverSigner(tx)
	require.NoError(t, err)
	assert.Equal(t, v.RootAddress, recovered.Account)
	assert.Equal(t, v.P256Address, recovered.KeyID)
	assert.Equal(t, signer.SignatureTypeKeychainV2, recovered.Keychain)

	_, err = VerifySignature(tx)
	assert.ErrorIs(t, err, ErrUnsupportedSignatureType)

	serialized, err := Serialize(tx, nil)
	require.NoError(t, err)
	assert.Equal(t, v.P256AccessKey.Serialized, serialized)
}

func TestDecodeSignatureEnvelope_Keychain(t *testing.T) {
	user := make([]byte, 20)
	p256 := append([]byte{signer.SignatureTypeP256}, make([]byte, signer.P256SignatureLength)...)
	webAuthn := append([]byte{signer.SignatureTypeWebAuthn}, make([]byte, 200)...)
	secp := make([]byte, 65)

	for name, envelope := range map[string][]byte{
		"v1 secp":     append(append([]byte{0x03}, user...), secp...),
		"v2 secp":     append(append([]byte{0x04}, user...), secp...),
		"v1 p256":     append(append([]byte{0x03}, user...), p256...),
		"v2 p256":     append(append([]byte{0x04}, user...), p256...),
		"v2 webauthn": append(append([]byte{0x04}, user...), webAuthn...),
	} {
		t.Run(name, func(t *testing.T) {
			decoded, err := decodeSignatureEnvelope(envelope)
			require.NoError(t, err)
			assert.Equal(t, "keychain", decoded.Type)
			encoded, err := encodeSignatureEnvelope(decoded)
			require.NoError(t, err)
			assert.Equal(t, envelope, encoded)
		})
	}

	for name, envelope := range map[string][]byte{
		"no inner":         append([]byte{0x04}, user...),
		"short user":       append([]byte{0x04}, user[:10]...),
		"bad inner length": append(append([]byte{0x04}, user...), make([]byte, 64)...),
		"bad inner type":   append(append([]byte{0x04}, user...), append([]byte{0x07}, make([]byte, 129)...)...),
		"nested keychain":  append(append([]byte{0x04}, user...), append(append([]byte{0x04}, user...), secp...)...),
	} {
		t.Run("rejects "+name, func(t *testing.T) {
			_, err := decodeSignatureEnvelope(envelope)
			assert.Error(t, err)
		})
	}
}

func TestVerifySignature_RejectsTamperedP256(t *testing.T) {
	v := loadViemTransactions(t)
	tx, err := Deserialize(v.P256Root.Serialized)
	require.NoError(t, err)
	tx.Nonce++
	_, err = VerifySignature(tx)
	assert.ErrorIs(t, err, signer.ErrInvalidEnvelope)
}

func TestSignTransactionWith_Secp256k1MatchesSignTransaction(t *testing.T) {
	s, err := signer.NewSigner("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	require.NoError(t, err)
	v := loadViemTransactions(t)
	base, err := Deserialize(v.P256Root.Serialized)
	require.NoError(t, err)
	base.Signature = nil

	a, b := base.Clone(), base.Clone()
	require.NoError(t, SignTransaction(a, s))
	require.NoError(t, SignTransactionWith(b, s))
	assert.Equal(t, a.Signature, b.Signature)
	sender, err := VerifySignature(b)
	require.NoError(t, err)
	assert.Equal(t, s.Address(), sender)
}
