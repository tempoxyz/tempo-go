package signer

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func FuzzSignAndVerify(f *testing.F) {
	f.Add([]byte("test message"))
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Add(make([]byte, 1024))

	f.Fuzz(func(t *testing.T, data []byte) {
		privateKey, err := crypto.GenerateKey()
		if err != nil {
			return
		}
		sgn := NewSignerFromKey(privateKey)

		sig, err := sgn.SignData(data)
		require.NoError(t, err)

		require.NotNil(t, sig.R)
		require.NotNil(t, sig.S)
		assert.LessOrEqual(t, sig.YParity, uint8(1))

		v := sig.V()
		assert.True(t, v == 27 || v == 28)

		hash := crypto.Keccak256Hash(data)
		valid, err := sgn.VerifySignature(hash, sig)
		require.NoError(t, err)
		assert.True(t, valid)

		recoveredAddr, err := RecoverAddress(hash, sig)
		require.NoError(t, err)
		assert.Equal(t, sgn.Address(), recoveredAddr)
	})
}

func FuzzRecoverAddressWithMalformedSignature(f *testing.F) {
	f.Add(
		[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		[]byte{0x01},
		[]byte{0x01},
		uint8(0),
	)

	f.Fuzz(func(t *testing.T, hashBytes, rBytes, sBytes []byte, yParity uint8) {
		var hash common.Hash
		if len(hashBytes) >= 32 {
			copy(hash[:], hashBytes[:32])
		} else if len(hashBytes) > 0 {
			copy(hash[32-len(hashBytes):], hashBytes)
		}

		r := new(big.Int).SetBytes(rBytes)
		s := new(big.Int).SetBytes(sBytes)
		sig := NewSignature(r, s, yParity)

		_, _ = RecoverAddress(hash, sig)
	})
}
