package transaction

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/require"
	"github.com/tempoxyz/tempo-go/pkg/signer"
)

func TestAuthorizationSigningAndRoundtrip(t *testing.T) {
	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	s := signer.NewSignerFromKey(key)
	a := SignedAuthorization{ChainID: new(big.Int), Address: common.HexToAddress("0x1234"), Nonce: 7}
	require.NoError(t, a.Sign(s))
	hash, err := a.SignatureHash()
	require.NoError(t, err)
	recovered, err := signer.RecoverAddress(hash, a.Signature.Signature)
	require.NoError(t, err)
	require.Equal(t, s.Address(), recovered)
	// Independent Ethereum authorization encoding has the same unsigned digest.
	payload, err := rlp.EncodeToBytes([]interface{}{uint64(0), a.Address, uint64(7)})
	require.NoError(t, err)
	require.Equal(t, crypto.Keccak256Hash([]byte{5}, payload), hash)
	tx := NewBuilder().SetGas(100000).AddCall(a.Address, nil, nil).SetAuthorizationList([]SignedAuthorization{a}).Build()
	require.NoError(t, SignTransaction(tx, s))
	encoded, err := Serialize(tx, nil)
	require.NoError(t, err)
	decoded, err := Deserialize(encoded)
	require.NoError(t, err)
	require.Equal(t, tx.AuthorizationList, decoded.AuthorizationList)
	reencoded, err := Serialize(decoded, nil)
	require.NoError(t, err)
	require.Equal(t, encoded, reencoded)
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
	for _, version := range []byte{3, 4} {
		for _, inner := range [][]byte{make([]byte, 65), append([]byte{1}, make([]byte, 129)...), append([]byte{2}, make([]byte, 128)...), append([]byte{2}, make([]byte, 2048)...)} {
			if len(inner) == 65 {
				inner[64] = 27
			}
			raw := append(append([]byte{version}, make([]byte, 20)...), inner...)
			decoded, err := decodeSignatureEnvelope(raw)
			require.NoError(t, err)
			require.Equal(t, "keychain", decoded.Type)
			again, err := encodeSignatureEnvelope(decoded)
			require.NoError(t, err)
			require.Equal(t, raw, again)
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

	keychain := append(append([]byte{4}, make([]byte, 20)...), make([]byte, 65)...)
	keychain[85] = 1
	decoded, err = decodeSignatureEnvelope(keychain)
	require.NoError(t, err)
	require.Equal(t, byte(28), decoded.Raw[85])
	require.Equal(t, byte(1), keychain[85], "must not mutate caller-owned signature")

	_, err = encodeSignatureEnvelope(&signer.SignatureEnvelope{Type: "p256", Raw: keychain})
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
