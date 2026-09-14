package transaction

import (
	"fmt"
	"math/big"
	"slices"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/require"
	"github.com/tempoxyz/tempo-go/pkg/signer"
)

// signedAuthorization returns a chain-agnostic delegation signed by a fresh key.
func signedAuthorization(t *testing.T) (SignedAuthorization, *signer.Signer) {
	t.Helper()
	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	s := signer.NewSignerFromKey(key)
	a := SignedAuthorization{ChainID: new(big.Int), Address: common.HexToAddress("0x1234"), Nonce: 7}
	require.NoError(t, a.Sign(s))
	return a, s
}

func txWithAuthorization(a SignedAuthorization) *Tx {
	return NewBuilder().SetGas(100000).AddCall(a.Address, nil, nil).SetAuthorizationList([]SignedAuthorization{a}).Build()
}

func TestAuthorizationSignatureHash(t *testing.T) {
	a, s := signedAuthorization(t)
	hash, err := a.SignatureHash()
	require.NoError(t, err)
	recovered, err := signer.RecoverAddress(hash, a.Signature.Signature)
	require.NoError(t, err)
	require.Equal(t, s.Address(), recovered)
	// Independent Ethereum authorization encoding has the same unsigned digest.
	payload, err := rlp.EncodeToBytes([]interface{}{uint64(0), a.Address, uint64(7)})
	require.NoError(t, err)
	require.Equal(t, crypto.Keccak256Hash([]byte{5}, payload), hash)
}

func TestAuthorizationRoundtrip(t *testing.T) {
	a, s := signedAuthorization(t)
	tx := txWithAuthorization(a)
	require.NoError(t, SignTransaction(tx, s))
	encoded, err := Serialize(tx, nil)
	require.NoError(t, err)
	decoded, err := Deserialize(encoded)
	require.NoError(t, err)
	require.Equal(t, tx.AuthorizationList, decoded.AuthorizationList)
	reencoded, err := Serialize(decoded, nil)
	require.NoError(t, err)
	require.Equal(t, encoded, reencoded)
}

func TestAuthorizationCloneIsolation(t *testing.T) {
	a, _ := signedAuthorization(t)
	tx := txWithAuthorization(a)
	before, err := GetSignPayload(tx)
	require.NoError(t, err)
	clone := tx.Clone()
	clone.AuthorizationList[0].ChainID.SetUint64(4217)
	clone.AuthorizationList[0].Signature.Signature.R.SetUint64(19)
	require.Zero(t, tx.AuthorizationList[0].ChainID.Sign())
	require.NotEqual(t, tx.AuthorizationList[0].Signature.Signature.R, clone.AuthorizationList[0].Signature.Signature.R)
	after, err := GetSignPayload(clone)
	require.NoError(t, err)
	require.NotEqual(t, before, after)
}

func TestExplicitZeroFeeToken(t *testing.T) {
	tx := NewBuilder().SetFeeToken(common.Address{}).Build()
	encoded, err := Serialize(tx, nil)
	require.NoError(t, err)
	decoded, err := Deserialize(encoded)
	require.NoError(t, err)
	require.True(t, decoded.FeeTokenSet)
	again, err := Serialize(decoded, nil)
	require.NoError(t, err)
	require.Equal(t, encoded, again)
	without := tx.Clone()
	without.FeeTokenSet = false
	other, err := Serialize(without, nil)
	require.NoError(t, err)
	require.NotEqual(t, encoded, other)
}

func TestDecodeZeroChainID(t *testing.T) {
	tx := NewDefault(0)
	encoded, err := Serialize(tx, nil)
	require.NoError(t, err)
	decoded, err := Deserialize(encoded)
	require.NoError(t, err)
	require.Zero(t, decoded.ChainID.Sign())
}

func TestKeychainPrimitiveEnvelopes(t *testing.T) {
	inners := []struct {
		name string
		raw  []byte
	}{
		{"secp256k1", append(make([]byte, 64), 27)},
		{"p256", append([]byte{1}, make([]byte, 129)...)},
		{"webauthn-min", append([]byte{2}, make([]byte, 128)...)},
		{"webauthn-max", append([]byte{2}, make([]byte, 2048)...)},
	}
	for _, version := range []byte{3, 4} {
		for _, inner := range inners {
			t.Run(fmt.Sprintf("v%d/%s", version, inner.name), func(t *testing.T) {
				raw := slices.Concat([]byte{version}, make([]byte, 20), inner.raw)
				decoded, err := decodeSignatureEnvelope(raw)
				require.NoError(t, err)
				require.Equal(t, "keychain", decoded.Type)
				again, err := encodeSignatureEnvelope(decoded)
				require.NoError(t, err)
				require.Equal(t, raw, again)
			})
		}
	}
}

func TestSignatureEnvelopeCanonicalizationAndValidation(t *testing.T) {
	p256 := append([]byte{1}, make([]byte, 129)...)
	p256[129] = 7
	decoded, err := decodeSignatureEnvelope(p256)
	require.NoError(t, err)
	require.Equal(t, byte(1), decoded.Raw[129])
	require.Equal(t, byte(7), p256[129], "must not mutate caller-owned signature")

	keychain := slices.Concat([]byte{4}, make([]byte, 20), make([]byte, 65))
	keychain[85] = 1
	decoded, err = decodeSignatureEnvelope(keychain)
	require.NoError(t, err)
	require.Equal(t, byte(28), decoded.Raw[85])
	require.Equal(t, byte(1), keychain[85], "must not mutate caller-owned signature")

	nested := slices.Concat([]byte{4}, make([]byte, 20), keychain)
	_, err = decodeSignatureEnvelope(nested)
	require.ErrorContains(t, err, "inner signature type")

	_, err = encodeSignatureEnvelope(&signer.SignatureEnvelope{Type: "p256", Raw: keychain})
	require.Error(t, err)
	_, err = encodeSignatureEnvelope(&signer.SignatureEnvelope{Type: "p256", Raw: []byte{}})
	require.Error(t, err)
	for _, sig := range []*signer.Signature{
		signer.NewSignature(nil, big.NewInt(1), 0),
		signer.NewSignature(big.NewInt(1), nil, 0),
		signer.NewSignature(big.NewInt(-1), big.NewInt(1), 0),
	} {
		_, err = encodeSignatureEnvelope(&signer.SignatureEnvelope{Type: "secp256k1", Signature: sig})
		require.Error(t, err)
	}
}

func TestValidateRustCallAuthorizationInvariants(t *testing.T) {
	callTarget := common.HexToAddress("0x1234")
	valid := NewBuilder().SetGas(100_000).AddCall(callTarget, nil, nil).Build()
	require.NoError(t, valid.Validate())

	secondCreate := valid.Clone()
	secondCreate.Calls = append(secondCreate.Calls, Call{Value: new(big.Int)})
	require.ErrorContains(t, secondCreate.Validate(), "only the first call")

	createWithAuthorization := valid.Clone()
	createWithAuthorization.Calls[0].To = nil
	createWithAuthorization.AuthorizationList = []SignedAuthorization{{}}
	require.ErrorContains(t, createWithAuthorization.Validate(), "not allowed with an authorization list")

	invalidWindow := valid.Clone()
	invalidWindow.ValidAfter = 10
	invalidWindow.ValidBefore = 10
	require.ErrorContains(t, invalidWindow.Validate(), "validBefore must be greater")
}

func TestAuthorizationValidation(t *testing.T) {
	for _, raw := range []interface{}{[]byte{}, []interface{}{[]interface{}{}}, []interface{}{[]interface{}{[]byte{}, []byte{}, []byte{}, []byte{}}}} {
		_, err := decodeAuthorizations(raw)
		require.Error(t, err)
	}
	for _, chain := range []*big.Int{nil, big.NewInt(-1), new(big.Int).Lsh(big.NewInt(1), 256)} {
		_, err := (SignedAuthorization{ChainID: chain}).SignatureHash()
		require.Error(t, err)
	}
}

func TestCanonicalRecoveryIDs(t *testing.T) {
	for _, parity := range []byte{0, 1} {
		envelope := signer.NewSignatureEnvelope(big.NewInt(1), big.NewInt(2), parity)
		encoded, err := encodeSignatureEnvelope(envelope)
		require.NoError(t, err)
		require.Equal(t, parity+27, encoded[64])
		// Both historical and canonical encodings recover the same public model.
		for _, wire := range []byte{parity, parity + 27} {
			encoded[64] = wire
			decoded, err := decodeSignatureEnvelope(encoded)
			require.NoError(t, err)
			require.Equal(t, parity, decoded.Signature.YParity)
		}
		raw := append(make([]byte, 21), encoded...)
		raw[0], raw[85] = 4, parity
		keychain, err := encodeSignatureEnvelope(&signer.SignatureEnvelope{Type: "keychain", Raw: raw})
		require.NoError(t, err)
		require.Equal(t, parity+27, keychain[85])
		require.Equal(t, parity, raw[85], "must not mutate caller-owned signature")
	}
}
