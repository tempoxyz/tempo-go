package keychain

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/tempoxyz/tempo-go/pkg/signer"
)

func FuzzBuildKeychainSignature(f *testing.F) {
	f.Add([]byte{1}, []byte{2})
	f.Add(bytes.Repeat([]byte{0xff}, 32), bytes.Repeat([]byte{0xff}, 32))
	f.Add(bytes.Repeat([]byte{0xff}, 33), []byte{1})
	f.Add([]byte{1}, bytes.Repeat([]byte{0xff}, 33))
	f.Add(bytes.Repeat([]byte{0xff}, 54), bytes.Repeat([]byte{0xff}, 86))

	root := common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	f.Fuzz(func(t *testing.T, rBytes, sBytes []byte) {
		if len(rBytes) > 128 || len(sBytes) > 128 {
			return
		}

		sig := signer.NewSignature(new(big.Int).SetBytes(rBytes), new(big.Int).SetBytes(sBytes), 1)
		encoded, err := BuildKeychainSignature(sig, root)
		if len(sig.R.Bytes()) > 32 || len(sig.S.Bytes()) > 32 {
			if err == nil {
				t.Fatalf("BuildKeychainSignature(%+v) returned %x; want error", sig, encoded)
			}
			return
		}
		if err != nil {
			t.Fatalf("BuildKeychainSignature(%+v) error = %v", sig, err)
		}
		_, gotRoot, got, err := ParseKeychainSignature(encoded)
		if err != nil {
			t.Fatalf("ParseKeychainSignature() error = %v", err)
		}
		if gotRoot != root {
			t.Fatalf("root = %s; want %s", gotRoot, root)
		}
		if got.R.Cmp(sig.R) != 0 || got.S.Cmp(sig.S) != 0 || got.YParity != sig.YParity {
			t.Fatalf("round-trip signature = %+v; want %+v", got, sig)
		}
	})
}
