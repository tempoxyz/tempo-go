package signer

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// FuzzRecoverEnvelope checks that arbitrary envelopes never panic and that
// any envelope that verifies recovers a non-zero account.
func FuzzRecoverEnvelope(f *testing.F) {
	v := loadViemVectors(f)
	for _, seed := range [][]byte{v.P256Signature, v.WebAuthnSignature, v.P256AccessKey, v.WebAuthnAccessKey, v.P256KeychainV1, {}, {0x04}} {
		f.Add(v.Hash.Bytes(), []byte(seed))
	}
	f.Fuzz(func(t *testing.T, hash, envelope []byte) {
		got, err := RecoverEnvelope(common.BytesToHash(hash), envelope)
		if err == nil && got.Account == (common.Address{}) && got.KeyID == (common.Address{}) {
			t.Fatalf("verified envelope recovered no signer")
		}
	})
}
