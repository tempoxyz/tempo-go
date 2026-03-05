// Package bech32m implements BIP-350 bech32m encoding and decoding.
package bech32m

import (
	"fmt"
	"strings"
)

const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

const bech32mConst = 0x2bc830a3

var charsetRev [128]int8

func init() {
	for i := range charsetRev {
		charsetRev[i] = -1
	}
	for i, c := range charset {
		charsetRev[c] = int8(i)
	}
}

func polymod(values []int) uint32 {
	gen := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (top>>uint(i))&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

func hrpExpand(hrp string) []int {
	out := make([]int, 0, len(hrp)*2+1)
	for _, c := range hrp {
		out = append(out, int(c>>5))
	}
	out = append(out, 0)
	for _, c := range hrp {
		out = append(out, int(c&31))
	}
	return out
}

func createChecksum(hrp string, data []int) []int {
	values := append(hrpExpand(hrp), data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	mod := polymod(values) ^ bech32mConst
	ret := make([]int, 6)
	for i := 0; i < 6; i++ {
		ret[i] = int((mod >> uint(5*(5-i))) & 31)
	}
	return ret
}

func verifyChecksum(hrp string, data []int) bool {
	return polymod(append(hrpExpand(hrp), data...)) == bech32mConst
}

// Encode encodes data as a bech32m string with the given human-readable part.
// The data must already be in 5-bit groups. Use ConvertBits to convert from 8-bit.
func Encode(hrp string, data []int) string {
	combined := append(data, createChecksum(hrp, data)...)
	var sb strings.Builder
	sb.Grow(len(hrp) + 1 + len(combined))
	sb.WriteString(hrp)
	sb.WriteByte('1')
	for _, d := range combined {
		sb.WriteByte(charset[d])
	}
	return sb.String()
}

// Decode decodes a bech32m string into its human-readable part and 5-bit data groups.
func Decode(s string) (string, []int, error) {
	lower := strings.ToLower(s)
	if lower != s && strings.ToUpper(s) != s {
		return "", nil, fmt.Errorf("mixed case")
	}
	s = lower
	pos := strings.LastIndexByte(s, '1')
	if pos < 1 || pos+7 > len(s) {
		return "", nil, fmt.Errorf("invalid separator position")
	}
	hrp := s[:pos]
	data := make([]int, 0, len(s)-pos-1)
	for _, c := range s[pos+1:] {
		if c > 127 || charsetRev[c] < 0 {
			return "", nil, fmt.Errorf("invalid character: %c", c)
		}
		data = append(data, int(charsetRev[c]))
	}
	if !verifyChecksum(hrp, data) {
		return "", nil, fmt.Errorf("invalid checksum")
	}
	return hrp, data[:len(data)-6], nil
}

// ConvertBits converts a byte slice from one bit-group size to another.
func ConvertBits(data []byte, fromBits, toBits uint8, pad bool) ([]byte, error) {
	acc := 0
	bits := uint8(0)
	maxv := (1 << toBits) - 1
	var ret []byte
	for _, value := range data {
		if int(value)>>fromBits != 0 {
			return nil, fmt.Errorf("invalid data byte: %d", value)
		}
		acc = (acc << fromBits) | int(value)
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			ret = append(ret, byte((acc>>bits)&maxv))
		}
	}
	if pad {
		if bits > 0 {
			ret = append(ret, byte((acc<<(toBits-bits))&maxv))
		}
	} else if bits >= fromBits || (acc<<(toBits-bits))&maxv != 0 {
		return nil, fmt.Errorf("invalid padding")
	}
	return ret, nil
}
