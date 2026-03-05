package address

import (
	"encoding/json"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testAddr is the address used across viem test vectors.
var testAddr = common.HexToAddress("0x742d35CC6634c0532925a3B844bc9e7595F2Bd28")

// TestViemVectors validates encoding against the canonical viem test vectors.
func TestViemVectors(t *testing.T) {
	tests := []struct {
		name     string
		addr     common.Address
		zoneID   *uint64
		expected string
	}{
		{
			name:     "mainnet_no_zone",
			addr:     testAddr,
			zoneID:   nil,
			expected: "tempo1qp6z6dwvvc6vq5efyk3ms39une6etu4a9qtj2kk0",
		},
		{
			name:     "zone_1",
			addr:     testAddr,
			zoneID:   uint64Ptr(1),
			expected: "tempoz1qqqhgtf4e3nrfszn9yj68wzyhj08t90jh55q74d9uj",
		},
		{
			name:     "zone_1000",
			addr:     testAddr,
			zoneID:   uint64Ptr(1000),
			expected: "tempoz1qr77sqm5956uce35cpfjjfdrhpzte8n4jhet62qxx4zvx",
		},
		{
			name:     "zone_65535",
			addr:     testAddr,
			zoneID:   uint64Ptr(65535),
			expected: "tempoz1qr7lllm5956uce35cpfjjfdrhpzte8n4jhet62q8pdj6j",
		},
		{
			name:     "zone_65536",
			addr:     testAddr,
			zoneID:   uint64Ptr(65536),
			expected: "tempoz1qrlqqqqpqp6z6dwvvc6vq5efyk3ms39une6etu4a9qdupk5c",
		},
		{
			name:     "zone_4294967295",
			addr:     testAddr,
			zoneID:   uint64Ptr(4294967295),
			expected: "tempoz1qrl0llllla6z6dwvvc6vq5efyk3ms39une6etu4a9qnk36qy",
		},
		{
			name:     "zone_4294967296",
			addr:     testAddr,
			zoneID:   uint64Ptr(4294967296),
			expected: "tempoz1qrlsqqqqqqqsqqqqwskntnrxxnq9x2f95wuyf0y7wk2l90fg4306kk",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ta TempoAddress
			if tt.zoneID != nil {
				ta = NewZoneTempoAddress(tt.addr, *tt.zoneID)
			} else {
				ta = NewTempoAddress(tt.addr)
			}

			// Encode
			encoded := ta.Format()
			assert.Equal(t, tt.expected, encoded, "encoding mismatch")

			// String() should match Format()
			assert.Equal(t, encoded, ta.String(), "String() should match Format()")

			// Decode
			parsed, err := ParseTempoAddress(tt.expected)
			require.NoError(t, err, "decode failed for %s", tt.expected)
			assert.Equal(t, tt.addr, parsed.EthAddress(), "address mismatch after decode")

			if tt.zoneID != nil {
				require.NotNil(t, parsed.ZoneID, "expected zone ID")
				assert.Equal(t, *tt.zoneID, *parsed.ZoneID, "zone ID mismatch")
			} else {
				assert.Nil(t, parsed.ZoneID, "expected no zone ID")
			}

			// Roundtrip
			assert.Equal(t, encoded, parsed.Format(), "roundtrip encoding mismatch")
		})
	}
}

// TestParseTempoAddress_Invalid tests various invalid address strings.
func TestParseTempoAddress_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty_string", ""},
		{"no_separator", "tempoabcdef"},
		{"wrong_hrp", "bitcoin1qp6z6dwvvc6vq5efyk3ms39une6etu4a9qtj2kk0"},
		{"truncated", "tempo1qp6z6dwvvc6vq5efyk3ms39une6etu4a"},
		{"bad_checksum", "tempo1qp6z6dwvvc6vq5efyk3ms39une6etu4a9qtj2kk1"},
		{"bad_character", "tempo1qp6z6dwvvc6vq5efyk3ms39une6etu4a9qtj2kb0"},
		{"mixed_case", "Tempo1qp6z6dwvvc6vq5efyk3ms39une6etu4a9qtj2kk0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseTempoAddress(tt.input)
			assert.Error(t, err)
			assert.False(t, ValidateTempoAddress(tt.input))
		})
	}
}

// TestValidateTempoAddress tests the validation helper.
func TestValidateTempoAddress(t *testing.T) {
	assert.True(t, ValidateTempoAddress("tempo1qp6z6dwvvc6vq5efyk3ms39une6etu4a9qtj2kk0"))
	assert.True(t, ValidateTempoAddress("tempoz1qqqhgtf4e3nrfszn9yj68wzyhj08t90jh55q74d9uj"))
	assert.False(t, ValidateTempoAddress(""))
	assert.False(t, ValidateTempoAddress("0x742d35CC6634c0532925a3B844bc9e7595F2Bd28"))
}

// TestNewTempoAddress_EthAddress verifies EthAddress returns the original address.
func TestNewTempoAddress_EthAddress(t *testing.T) {
	addr := common.HexToAddress("0x0000000000000000000000000000000000000001")
	ta := NewTempoAddress(addr)
	assert.Equal(t, addr, ta.EthAddress())
	assert.Nil(t, ta.ZoneID)
}

// TestNewZoneTempoAddress_EthAddress verifies zone address preserves both fields.
func TestNewZoneTempoAddress_EthAddress(t *testing.T) {
	addr := common.HexToAddress("0x0000000000000000000000000000000000000001")
	ta := NewZoneTempoAddress(addr, 42)
	assert.Equal(t, addr, ta.EthAddress())
	require.NotNil(t, ta.ZoneID)
	assert.Equal(t, uint64(42), *ta.ZoneID)
}

// TestJSONRoundtrip tests JSON marshal/unmarshal.
func TestJSONRoundtrip(t *testing.T) {
	type wrapper struct {
		Addr TempoAddress `json:"addr"`
	}

	tests := []struct {
		name     string
		ta       TempoAddress
		expected string
	}{
		{
			name:     "mainnet",
			ta:       NewTempoAddress(testAddr),
			expected: `{"addr":"tempo1qp6z6dwvvc6vq5efyk3ms39une6etu4a9qtj2kk0"}`,
		},
		{
			name:     "zone",
			ta:       NewZoneTempoAddress(testAddr, 1),
			expected: `{"addr":"tempoz1qqqhgtf4e3nrfszn9yj68wzyhj08t90jh55q74d9uj"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := wrapper{Addr: tt.ta}
			data, err := json.Marshal(w)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, string(data))

			var decoded wrapper
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)
			assert.Equal(t, tt.ta.Address, decoded.Addr.Address)

			if tt.ta.ZoneID != nil {
				require.NotNil(t, decoded.Addr.ZoneID)
				assert.Equal(t, *tt.ta.ZoneID, *decoded.Addr.ZoneID)
			} else {
				assert.Nil(t, decoded.Addr.ZoneID)
			}
		})
	}
}

// TestJSONUnmarshal_Invalid tests that invalid JSON is rejected.
func TestJSONUnmarshal_Invalid(t *testing.T) {
	var ta TempoAddress

	// Not a string
	assert.Error(t, json.Unmarshal([]byte(`123`), &ta))

	// Invalid address
	assert.Error(t, json.Unmarshal([]byte(`"not-an-address"`), &ta))
}

// TestTextMarshalUnmarshal tests encoding.TextMarshaler/TextUnmarshaler.
func TestTextMarshalUnmarshal(t *testing.T) {
	ta := NewTempoAddress(testAddr)

	text, err := ta.MarshalText()
	require.NoError(t, err)
	assert.Equal(t, "tempo1qp6z6dwvvc6vq5efyk3ms39une6etu4a9qtj2kk0", string(text))

	var decoded TempoAddress
	err = decoded.UnmarshalText(text)
	require.NoError(t, err)
	assert.Equal(t, ta.Address, decoded.Address)
	assert.Nil(t, decoded.ZoneID)
}

// TestCompactSizeEncoding tests the CompactSize encoding at all boundary values.
func TestCompactSizeEncoding(t *testing.T) {
	tests := []struct {
		value    uint64
		expected []byte
	}{
		{0, []byte{0x00}},
		{1, []byte{0x01}},
		{252, []byte{0xFC}},
		{253, []byte{0xFD, 0xFD, 0x00}},
		{1000, []byte{0xFD, 0xE8, 0x03}},
		{65535, []byte{0xFD, 0xFF, 0xFF}},
		{65536, []byte{0xFE, 0x00, 0x00, 0x01, 0x00}},
		{4294967295, []byte{0xFE, 0xFF, 0xFF, 0xFF, 0xFF}},
		{4294967296, []byte{0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}},
	}

	for _, tt := range tests {
		encoded := encodeCompactSize(tt.value)
		assert.Equal(t, tt.expected, encoded, "encode mismatch for %d", tt.value)

		decoded, n, err := decodeCompactSize(encoded)
		require.NoError(t, err, "decode failed for %d", tt.value)
		assert.Equal(t, tt.value, decoded, "decode mismatch for %d", tt.value)
		assert.Equal(t, len(tt.expected), n, "consumed bytes mismatch for %d", tt.value)
	}
}

// TestCompactSizeDecode_Invalid tests CompactSize decoding with truncated data.
func TestCompactSizeDecode_Invalid(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"truncated_fd", []byte{0xFD, 0x01}},
		{"truncated_fe", []byte{0xFE, 0x01, 0x02}},
		{"truncated_ff", []byte{0xFF, 0x01, 0x02, 0x03, 0x04}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := decodeCompactSize(tt.data)
			assert.Error(t, err)
		})
	}
}

// TestZeroAddress tests encoding/decoding of the zero address.
func TestZeroAddress(t *testing.T) {
	ta := NewTempoAddress(common.Address{})
	encoded := ta.Format()

	parsed, err := ParseTempoAddress(encoded)
	require.NoError(t, err)
	assert.Equal(t, common.Address{}, parsed.EthAddress())
	assert.Nil(t, parsed.ZoneID)
}

// TestCaseInsensitiveParsing verifies that uppercase input is accepted.
func TestCaseInsensitiveParsing(t *testing.T) {
	upper := "TEMPO1QP6Z6DWVVC6VQ5EFYK3MS39UNE6ETU4A9QTJ2KK0"
	parsed, err := ParseTempoAddress(upper)
	require.NoError(t, err)
	assert.Equal(t, testAddr, parsed.EthAddress())
}

func uint64Ptr(v uint64) *uint64 {
	return &v
}
