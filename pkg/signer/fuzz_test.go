package signer

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// FuzzSignAndVerify tests the sign -> verify round trip.
func FuzzSignAndVerify(f *testing.F) {
	f.Add([]byte("test message"))
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Add(make([]byte, 1024))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			data = data[:4096]
		}

		privateKey, err := crypto.GenerateKey()
		if err != nil {
			return
		}
		sgn := NewSignerFromKey(privateKey)

		sig, err := sgn.SignData(data)
		require.NoError(t, err, "failed to sign data")

		require.NotNil(t, sig.R, "signature R is nil")
		require.NotNil(t, sig.S, "signature S is nil")
		assert.LessOrEqual(t, sig.YParity, uint8(1), "YParity should be 0 or 1")

		v := sig.V()
		assert.True(t, v == 27 || v == 28, "V should be 27 or 28, got %d", v)

		hash := crypto.Keccak256Hash(data)
		valid, err := sgn.VerifySignature(hash, sig)
		require.NoError(t, err, "failed to verify signature")
		assert.True(t, valid, "signature verification failed for data we just signed")

		recoveredAddr, err := RecoverAddress(hash, sig)
		require.NoError(t, err, "failed to recover address")
		assert.Equal(t, sgn.Address(), recoveredAddr, "recovered address mismatch")
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
		// clip to 32 bytes
		if len(hashBytes) >= 32 {
			copy(hash[:], hashBytes[:32])
		} else if len(hashBytes) > 0 {
			copy(hash[32-len(hashBytes):], hashBytes)
		}

		// clip to 32 bytes
		if len(rBytes) > 32 {
			rBytes = rBytes[:32]
		}
		if len(sBytes) > 32 {
			sBytes = sBytes[:32]
		}

		r := new(big.Int).SetBytes(rBytes)
		s := new(big.Int).SetBytes(sBytes)

		sig := NewSignature(r, s, yParity%2)

		// never panic
		_, _ = RecoverAddress(hash, sig)
	})
}
