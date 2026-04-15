package client

import (
	"math/big"
	"testing"
)

func FuzzParseHexUint64(f *testing.F) {
	f.Add("0x0")
	f.Add("0x1a")
	f.Add("ff")
	f.Add("")
	f.Add("0xzz")

	f.Fuzz(func(t *testing.T, input string) {
		value, err := parseHexUint64(input)
		if err == nil {
			_ = value
		}
	})
}

func FuzzParseHexBigInt(f *testing.F) {
	f.Add("0x")
	f.Add("0x1a")
	f.Add("ff")
	f.Add("0xffffffffffffffffffffffffffffffff")
	f.Add("0xzz")

	f.Fuzz(func(t *testing.T, input string) {
		value, err := parseHexBigInt(input)
		if err == nil && value != nil {
			_ = new(big.Int).Set(value)
		}
	})
}
