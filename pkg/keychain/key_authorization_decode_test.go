package keychain

import (
	"bytes"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/tempoxyz/tempo-go/pkg/signer"
	"github.com/tempoxyz/tempo-go/pkg/transaction"
)

// rlpRoundTrip encodes v and decodes it back into the generic shape
// transaction.Deserialize produces for Tx.KeyAuthorization.
func rlpRoundTrip(t *testing.T, v []interface{}) []interface{} {
	t.Helper()
	encoded, err := rlp.EncodeToBytes(v)
	if err != nil {
		t.Fatalf("rlp encode: %v", err)
	}
	var out []interface{}
	if err := rlp.DecodeBytes(encoded, &out); err != nil {
		t.Fatalf("rlp decode: %v", err)
	}
	return out
}

func mustRLP(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := rlp.EncodeToBytes(v)
	if err != nil {
		t.Fatalf("rlp encode: %v", err)
	}
	return b
}

func TestDecodeKeyAuthorization_RoundTrip(t *testing.T) {
	s, err := signer.NewSigner(rootKeyPrivate)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	token := common.HexToAddress("0x20c0000000000000000000000000000000000001")
	account := common.HexToAddress("0x2222222222222222222222222222222222222222")
	recipient := common.HexToAddress("0x3333333333333333333333333333333333333333")
	maxU256 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))

	cases := map[string]*KeyAuthorization{
		"unrestricted": NewKeyAuthorization(1, SignatureTypeSecp256k1, testKeyID()),
		"expiry":       NewKeyAuthorization(1, SignatureTypeP256, testKeyID()).WithExpiry(4102444800),
		"limits": NewKeyAuthorization(42431, SignatureTypeWebAuthn, testKeyID()).WithLimits([]TokenLimit{
			{Token: token, Amount: big.NewInt(5000000), Period: 86400},
			{Token: account, Amount: maxU256},
			{Token: recipient, Amount: big.NewInt(0)},
		}),
		"no spending": NewKeyAuthorization(1, SignatureTypeSecp256k1, testKeyID()).WithNoSpending(),
		"allowed calls": NewKeyAuthorization(1, SignatureTypeSecp256k1, testKeyID()).WithAllowedCalls([]CallScope{
			{Target: token, SelectorRules: []SelectorRule{
				{Selector: [4]byte{0xa9, 0x05, 0x9c, 0xbb}, Recipients: []common.Address{recipient, account}},
				{Selector: [4]byte{0x09, 0x5e, 0xa7, 0xb3}, Recipients: []common.Address{}},
			}},
			{Target: account, SelectorRules: []SelectorRule{}},
		}),
		"no calls":     NewKeyAuthorization(1, SignatureTypeSecp256k1, testKeyID()).WithNoCalls(),
		"zero witness": NewKeyAuthorization(1, SignatureTypeSecp256k1, testKeyID()).WithWitness(common.Hash{}),
		"admin":        NewKeyAuthorization(1, SignatureTypeSecp256k1, testKeyID()).IntoAdmin(account),
		"account only": NewKeyAuthorization(1, SignatureTypeSecp256k1, testKeyID()).WithExpiry(10).WithAccount(account),
	}

	for name, auth := range cases {
		t.Run(name, func(t *testing.T) {
			signed, err := auth.Sign(s)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			for form, input := range map[string][]interface{}{"built": signed, "rlp": rlpRoundTrip(t, signed)} {
				got, sig, err := DecodeKeyAuthorization(input)
				if err != nil {
					t.Fatalf("%s: DecodeKeyAuthorization: %v", form, err)
				}
				if !bytes.Equal(sig, signed[1].([]byte)) {
					t.Errorf("%s: signature = %x, want %x", form, sig, signed[1])
				}
				wantHash, _ := auth.SignatureHash()
				gotHash, err := got.SignatureHash()
				if err != nil {
					t.Fatalf("%s: SignatureHash of decoded: %v", form, err)
				}
				if gotHash != wantHash {
					t.Errorf("%s: decoded authorization hash = %s, want %s", form, gotHash, wantHash)
				}
				rebuilt, err := got.BuildSigned(sig)
				if err != nil {
					t.Fatalf("%s: BuildSigned: %v", form, err)
				}
				if !bytes.Equal(mustRLP(t, rebuilt), mustRLP(t, signed)) {
					t.Errorf("%s: re-encoded authorization differs from the original", form)
				}
				if (got.Limits == nil) != (auth.Limits == nil) || (got.AllowedCalls == nil) != (auth.AllowedCalls == nil) ||
					(got.Witness == nil) != (auth.Witness == nil) || (got.Account == nil) != (auth.Account == nil) ||
					got.IsAdmin != auth.IsAdmin || got.Expiry != auth.Expiry || got.KeyType != auth.KeyType ||
					got.ChainID != auth.ChainID || got.KeyID != auth.KeyID {
					t.Errorf("%s: decoded %+v, want %+v", form, got, auth)
				}
			}
		})
	}
}

// Transactions signed by viem/ox, from tempo-conformance vectors/decode.json
// (decode_key_authorization_expiry_periodic_limit and decode_key_authorization_no_spending).
const (
	conformanceKeyAuthPeriodicTx   = "0x76f90141820539843b9aca00850ba43b7400831e8480f85ef85c9420c000000000000000000000000000000000000080b844a9059cbb000000000000000000000000000000000000000000000000000000000000beef0000000000000000000000000000000000000000000000000000000000000001c0808080808080c0f882f83d820539809480abf92f6b72752d3847873a704bdb11c033c9a584f4865700dedd9420c0000000000000000000000000000000000000834c4b4083015180b841650493a5c44f0e6595259a5d7b911ead832a6a2bca31bc4cb4b934017c4194d657b730348fe748153c49eff585e71952d320f09b97f8ecf3734efe2fb2c728b31cb841ea50fa1e7165fbd7ae19861ac01acfea18790aaa5799aafbcb7a16a9134a9d736fbafe21f3f97b35a4d9813ec5a87f93dd7f0ee4ff48db9d4d61ca3bbba9841f1c"
	conformanceKeyAuthNoSpendingTx = "0x76f9011e820539843b9aca00850ba43b7400831e8480f85ef85c9420c000000000000000000000000000000000000080b844a9059cbb000000000000000000000000000000000000000000000000000000000000beef0000000000000000000000000000000000000000000000000000000000000001c0808080808080c0f85fdb8205398094b73999ba00a056a736c9cfcfaa627c265db62b6d80c0b841853f5fc8a4ddfbf797f111bdf6e17f3b25b92bfb5bbcd4cb6a60bf7243378e7f617e7c8331718792b5aa8ee9bc34f270d4c19af0e0f08f6c1c25810bd48cb02b1bb8417edf0f6a47617c212414be5acec49d6a632e39404e112f00dd7a54258d5821525f54fdaa41a2d5b6c290972c0526b93b10d58408e5723d8fd11558e253dbad201c"
)

func TestDecodeKeyAuthorization_FromTransaction(t *testing.T) {
	tx, err := transaction.Deserialize(conformanceKeyAuthPeriodicTx)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	auth, sig, err := DecodeKeyAuthorization(tx.KeyAuthorization)
	if err != nil {
		t.Fatalf("DecodeKeyAuthorization: %v", err)
	}
	if auth.ChainID != 1337 || auth.KeyType != SignatureTypeSecp256k1 || auth.Expiry != 4102444800 {
		t.Errorf("unexpected authorization: %+v", auth)
	}
	if auth.KeyID != common.HexToAddress("0x80abf92f6b72752d3847873a704bdb11c033c9a5") {
		t.Errorf("keyId = %s", auth.KeyID.Hex())
	}
	if auth.Limits == nil || len(*auth.Limits) != 1 {
		t.Fatalf("limits = %v, want one limit", auth.Limits)
	}
	limit := (*auth.Limits)[0]
	if limit.Token != common.HexToAddress("0x20c0000000000000000000000000000000000000") ||
		limit.Amount.Cmp(big.NewInt(5000000)) != 0 || limit.Period != 86400 {
		t.Errorf("limit = %+v", limit)
	}
	if auth.AllowedCalls != nil || auth.Witness != nil || auth.IsAdmin || auth.Account != nil {
		t.Errorf("unexpected optional fields: %+v", auth)
	}

	// The root account (the transaction's sender) signed the authorization.
	hash, err := auth.SignatureHash()
	if err != nil {
		t.Fatalf("SignatureHash: %v", err)
	}
	if sig[64] != 27 && sig[64] != 28 {
		t.Fatalf("signature v = %d, want 27/28", sig[64])
	}
	signerAddr, err := signer.RecoverAddress(hash, signer.NewSignature(
		new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:64]), sig[64]-27))
	if err != nil {
		t.Fatalf("RecoverAddress: %v", err)
	}
	sender, err := transaction.VerifySignature(tx)
	if err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
	if want := common.HexToAddress("0x123f68c947a95a862624b693981adbc31c804922"); signerAddr != want || sender != want {
		t.Errorf("authorization signer = %s, sender = %s, want %s", signerAddr.Hex(), sender.Hex(), want.Hex())
	}

	tx, err = transaction.Deserialize(conformanceKeyAuthNoSpendingTx)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	auth, _, err = DecodeKeyAuthorization(tx.KeyAuthorization)
	if err != nil {
		t.Fatalf("DecodeKeyAuthorization: %v", err)
	}
	if auth.Limits == nil || len(*auth.Limits) != 0 || auth.Expiry != 0 {
		t.Errorf("want no spending and no expiry, got %+v", auth)
	}
}

func TestDecodeKeyAuthorization_AcceptsZeroOneRecoveryID(t *testing.T) {
	s, err := signer.NewSigner(rootKeyPrivate)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	signed, err := NewKeyAuthorization(1, SignatureTypeSecp256k1, testKeyID()).Sign(s)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	canonical := signed[1].([]byte)
	zeroOne := append([]byte(nil), canonical...)
	zeroOne[64] -= 27

	_, sig, err := DecodeKeyAuthorization([]interface{}{signed[0], zeroOne})
	if err != nil {
		t.Fatalf("DecodeKeyAuthorization: %v", err)
	}
	if !bytes.Equal(sig, canonical) {
		t.Errorf("signature = %x, want 27/28 form %x", sig, canonical)
	}
}

func TestDecodeKeyAuthorization_Rejects(t *testing.T) {
	keyID := testKeyID().Bytes()
	addr := common.HexToAddress("0x2222222222222222222222222222222222222222").Bytes()
	sig := make([]byte, 65)
	sig[64] = 27
	auth := func(fields ...interface{}) []interface{} {
		return []interface{}{append([]interface{}{[]byte{0x01}, []byte{}, keyID}, fields...), sig}
	}
	empty := []byte{}
	list := []interface{}{}

	cases := []struct {
		name   string
		signed []interface{}
		want   string
	}{
		{"one item", []interface{}{auth()[0]}, "expected 2 items"},
		{"authorization not a list", []interface{}{[]byte{1}, sig}, "not a list"},
		{"signature not bytes", []interface{}{auth()[0], list}, "not a byte string"},
		{"too few fields", []interface{}{[]interface{}{[]byte{1}, empty}, sig}, "expected 3 to 9 fields"},
		{"too many fields", auth(empty, empty, empty, empty, empty, addr, addr), "expected 3 to 9 fields"},
		{"chainId leading zero", []interface{}{[]interface{}{[]byte{0, 1}, empty, keyID}, sig}, "leading zero"},
		{"chainId over uint64", []interface{}{[]interface{}{bytes.Repeat([]byte{1}, 9), empty, keyID}, sig}, "exceeds uint64"},
		{"keyType unsupported", []interface{}{[]interface{}{[]byte{1}, []byte{3}, keyID}, sig}, "unsupported keyType"},
		{"keyId short", []interface{}{[]interface{}{[]byte{1}, empty, keyID[:19]}, sig}, "20-byte address"},
		{"trailing expiry placeholder", auth(empty), "omitted"},
		{"trailing limits placeholder", auth(empty, empty), "limits is not a list"},
		{"trailing witness placeholder", auth(empty, empty, empty, empty), "witness"},
		{"limits not a list", auth(empty, []byte{1}), "limits is not a list"},
		{"limit tuple too short", auth(empty, []interface{}{[]interface{}{addr}}), "2 or 3 items"},
		{"limit amount over uint256", auth(empty, []interface{}{[]interface{}{addr, bytes.Repeat([]byte{1}, 33)}}), "exceeds uint256"},
		{"limit period zero", auth(empty, []interface{}{[]interface{}{addr, []byte{1}, empty}}), "period must be omitted"},
		{"selector wrong size", auth(empty, empty, []interface{}{[]interface{}{addr, []interface{}{[]interface{}{[]byte{1, 2, 3}, list}}}}), "4 bytes"},
		{"call scope extra item", auth(empty, empty, []interface{}{[]interface{}{addr, list, list}}), "2 items"},
		{"admin marker not 1", auth(empty, empty, empty, empty, []byte{2}, addr), "admin key authorization marker"},
		{"account wrong size", auth(empty, empty, empty, empty, []byte{1}, keyID[:4]), "20-byte address"},
		{"bad recovery id", []interface{}{auth()[0], append(make([]byte, 64), 29)}, "recovery id"},
		{"bad signature length", []interface{}{auth()[0], make([]byte, 64)}, "invalid primitive signature"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := DecodeKeyAuthorization(tc.signed)
			if err == nil {
				t.Fatalf("expected error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}
