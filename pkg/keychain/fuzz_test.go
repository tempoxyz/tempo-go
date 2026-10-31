package keychain

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
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

func FuzzDecodeKeyAuthorization(f *testing.F) {
	s, err := signer.NewSigner(rootKeyPrivate)
	if err != nil {
		f.Fatal(err)
	}
	account := common.HexToAddress("0x2222222222222222222222222222222222222222")
	for _, auth := range []*KeyAuthorization{
		NewKeyAuthorization(1, SignatureTypeSecp256k1, account),
		NewKeyAuthorization(1, SignatureTypeP256, account).WithExpiry(10).WithLimits([]TokenLimit{{Token: account, Amount: big.NewInt(1), Period: 5}}),
		NewKeyAuthorization(1, SignatureTypeSecp256k1, account).WithAllowedCalls([]CallScope{{Target: account, SelectorRules: []SelectorRule{{Recipients: []common.Address{account}}}}}),
		NewKeyAuthorization(1, SignatureTypeSecp256k1, account).WithWitness(common.Hash{}).IntoAdmin(account),
	} {
		signed, err := auth.Sign(s)
		if err != nil {
			f.Fatal(err)
		}
		encoded, err := rlp.EncodeToBytes(signed)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(encoded)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var raw []interface{}
		if err := rlp.DecodeBytes(data, &raw); err != nil {
			return
		}
		auth, sig, err := DecodeKeyAuthorization(raw)
		if err != nil {
			return
		}
		if auth.Validate() != nil {
			return
		}
		// A decoded authorization re-encodes to a value that decodes to the same authorization.
		rebuilt, err := auth.BuildSigned(sig)
		if err != nil {
			t.Fatalf("BuildSigned of decoded authorization: %v", err)
		}
		again, sig2, err := DecodeKeyAuthorization(rlpRoundTrip(t, rebuilt))
		if err != nil {
			t.Fatalf("DecodeKeyAuthorization of re-encoded authorization: %v", err)
		}
		h1, _ := auth.SignatureHash()
		h2, _ := again.SignatureHash()
		if h1 != h2 || !bytes.Equal(sig, sig2) {
			t.Fatalf("re-encoded authorization decodes differently")
		}
	})
}
