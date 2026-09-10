package transaction

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

func baseList(t *testing.T) []interface{} {
	t.Helper()
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	tx := New()
	tx.Gas = 21000
	tx.MaxFeePerGas = big.NewInt(1)
	tx.Calls = []Call{{To: &to, Value: big.NewInt(7), Data: []byte{}}}
	list, err := buildRLPList(tx, &SerializeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return list
}

func wire(t *testing.T, list []interface{}) string {
	t.Helper()
	raw, err := rlp.EncodeToBytes(list)
	if err != nil {
		t.Fatal(err)
	}
	return "0x76" + hex.EncodeToString(raw)
}

func TestDeserialize_RejectsNonCanonicalIntegers(t *testing.T) {
	cases := []struct {
		name string
		idx  int
		val  []byte
	}{
		{"chainId", 0, []byte{0x00, 0x10, 0x79}},
		{"maxPriorityFee", 1, []byte{0x00, 0x01}},
		{"maxFee", 2, []byte{0x00, 0x01}},
		{"gas", 3, []byte{0x00, 0x52, 0x08}},
		{"nonceKey", 6, []byte{0x00, 0x01}},
		{"nonce", 7, []byte{0x00, 0x05}},
		{"validBefore", 8, []byte{0x00, 0x05}},
		{"validAfter", 9, []byte{0x00, 0x05}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			list := baseList(t)
			list[tc.idx] = tc.val
			if _, err := Deserialize(wire(t, list)); err == nil {
				t.Fatalf("%s: expected non-canonical integer to be rejected", tc.name)
			}
		})
	}
}

func TestDeserialize_RejectsNonCanonicalCallValue(t *testing.T) {
	list := baseList(t)
	call := []interface{}{
		common.HexToAddress("0x2222222222222222222222222222222222222222").Bytes(),
		[]byte{0x00, 0x07}, // non-canonical value
		[]byte{},
	}
	list[4] = []interface{}{call}
	if _, err := Deserialize(wire(t, list)); err == nil {
		t.Fatal("expected non-canonical call value to be rejected")
	}
}

// Canonical encodings (incl. zero as empty string) still deserialize fine.
func TestDeserialize_AcceptsCanonicalIntegers(t *testing.T) {
	if _, err := Deserialize(wire(t, baseList(t))); err != nil {
		t.Fatalf("canonical transaction rejected: %v", err)
	}
}
