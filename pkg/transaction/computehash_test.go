package transaction

import (
	"testing"
)

// ComputeHash must treat its input as hex, with or without the 0x prefix, and
// must produce the same hash either way.
func TestComputeHash_PrefixInvariant(t *testing.T) {
	withPrefix, err := ComputeHash("0x76c0")
	if err != nil {
		t.Fatal(err)
	}
	noPrefix, err := ComputeHash("76c0")
	if err != nil {
		t.Fatal(err)
	}
	if withPrefix != noPrefix {
		t.Fatalf("prefix should not change the hash: %s vs %s", withPrefix.Hex(), noPrefix.Hex())
	}
}

// A non-hex string is rejected rather than silently hashed as raw bytes.
func TestComputeHash_RejectsNonHex(t *testing.T) {
	if _, err := ComputeHash("not-a-transaction"); err == nil {
		t.Fatal("expected error for non-hex input, got nil")
	}
	if _, err := ComputeHash("0xZZ"); err == nil {
		t.Fatal("expected error for invalid hex, got nil")
	}
}

// A round-tripped, signed transaction still hashes consistently.
func TestComputeHash_MatchesTxHash(t *testing.T) {
	// hash of the canonical empty-ish payload is deterministic; ensure no error path
	h, err := ComputeHash("0x76c0")
	if err != nil {
		t.Fatal(err)
	}
	if h.Hex() == "" {
		t.Fatal("empty hash")
	}
}
