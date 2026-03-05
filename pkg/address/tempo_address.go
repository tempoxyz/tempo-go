// Package address provides Bech32m encoding and decoding for Tempo addresses.
//
// Tempo uses Bech32m (BIP-350) to encode Ethereum-compatible 20-byte addresses
// into human-readable strings. Two formats are supported:
//
//   - Mainnet addresses: hrp "tempo", payload = [0x00 version] [20-byte address]
//   - Zone addresses:    hrp "tempoz", payload = [0x00 version] [compact_size zone_id] [20-byte address]
//
// # Basic Usage
//
//	addr := common.HexToAddress("0x742d35CC6634c0532925a3B844bc9e7595F2Bd28")
//	ta := address.NewTempoAddress(addr)
//	fmt.Println(ta) // "tempo1qp6z6dwvvc6vq5efyk3ms39une6etu4a9qtj2kk0"
//
//	parsed, err := address.ParseTempoAddress("tempo1qp6z6dwvvc6vq5efyk3ms39une6etu4a9qtj2kk0")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(parsed.EthAddress().Hex())
//
// # Zone Addresses
//
//	ta := address.NewZoneTempoAddress(addr, 1)
//	fmt.Println(ta) // "tempoz1qqqhgtf4e3nrfszn9yj68wzyhj08t90jh55q74d9uj"
package address

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/tempoxyz/tempo-go/internal/bech32m"
)

// Human-readable part prefixes.
const (
	hrpMainnet = "tempo"
	hrpZone    = "tempoz"
)

// Version byte for the current address format.
const versionByte = 0x00

// Sentinel errors for address operations.
var (
	// ErrInvalidAddress is returned when a Bech32m address string cannot be parsed.
	ErrInvalidAddress = errors.New("invalid tempo address")

	// ErrInvalidVersion is returned when the address version byte is not supported.
	ErrInvalidVersion = errors.New("unsupported address version")

	// ErrInvalidHRP is returned when the human-readable part is not "tempo" or "tempoz".
	ErrInvalidHRP = errors.New("invalid address prefix")

	// ErrInvalidChecksum is returned when the Bech32m checksum verification fails.
	ErrInvalidChecksum = errors.New("invalid bech32m checksum")

	// ErrInvalidPayload is returned when the decoded payload has unexpected length.
	ErrInvalidPayload = errors.New("invalid address payload")
)

// TempoAddress represents a Tempo address with optional zone information.
type TempoAddress struct {
	// Address is the underlying 20-byte Ethereum address.
	Address common.Address

	// ZoneID is the optional zone identifier. Nil means a mainnet (non-zone) address.
	ZoneID *uint64
}

// NewTempoAddress creates a TempoAddress without a zone (mainnet address).
func NewTempoAddress(addr common.Address) TempoAddress {
	return TempoAddress{Address: addr}
}

// NewZoneTempoAddress creates a TempoAddress with a zone identifier.
func NewZoneTempoAddress(addr common.Address, zoneID uint64) TempoAddress {
	z := zoneID
	return TempoAddress{Address: addr, ZoneID: &z}
}

// Format encodes the TempoAddress to a Bech32m string.
func (a TempoAddress) Format() string {
	hrp := hrpMainnet
	var payload []byte

	if a.ZoneID != nil {
		hrp = hrpZone
		zoneBytes := encodeCompactSize(*a.ZoneID)
		payload = make([]byte, 1+len(zoneBytes)+20)
		payload[0] = versionByte
		copy(payload[1:], zoneBytes)
		copy(payload[1+len(zoneBytes):], a.Address[:])
	} else {
		payload = make([]byte, 21)
		payload[0] = versionByte
		copy(payload[1:], a.Address[:])
	}

	conv, err := bech32m.ConvertBits(payload, 8, 5, true)
	if err != nil {
		panic(fmt.Sprintf("address: convert bits failed: %v", err))
	}
	data5 := make([]int, len(conv))
	for i, b := range conv {
		data5[i] = int(b)
	}
	return bech32m.Encode(hrp, data5)
}

// String implements fmt.Stringer. Returns the Bech32m-encoded address string.
func (a TempoAddress) String() string {
	return a.Format()
}

// EthAddress returns the underlying 20-byte Ethereum address.
func (a TempoAddress) EthAddress() common.Address {
	return a.Address
}

// MarshalText implements encoding.TextMarshaler.
func (a TempoAddress) MarshalText() ([]byte, error) {
	return []byte(a.Format()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (a *TempoAddress) UnmarshalText(text []byte) error {
	parsed, err := ParseTempoAddress(string(text))
	if err != nil {
		return err
	}
	*a = parsed
	return nil
}

// MarshalJSON implements json.Marshaler. Encodes as a JSON string.
func (a TempoAddress) MarshalJSON() ([]byte, error) {
	return []byte(`"` + a.Format() + `"`), nil
}

// UnmarshalJSON implements json.Unmarshaler. Decodes from a JSON string.
func (a *TempoAddress) UnmarshalJSON(data []byte) error {
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return fmt.Errorf("%w: expected JSON string", ErrInvalidAddress)
	}
	return a.UnmarshalText(data[1 : len(data)-1])
}

// ParseTempoAddress decodes a Bech32m string into a TempoAddress.
func ParseTempoAddress(s string) (TempoAddress, error) {
	hrp, data5, err := bech32m.Decode(s)
	if err != nil {
		return TempoAddress{}, fmt.Errorf("%w: %v", ErrInvalidAddress, err)
	}
	data := make([]byte, len(data5))
	for i, v := range data5 {
		data[i] = byte(v)
	}
	payload, err := bech32m.ConvertBits(data, 5, 8, false)
	if err != nil {
		return TempoAddress{}, fmt.Errorf("%w: %v", ErrInvalidAddress, err)
	}

	switch hrp {
	case hrpMainnet:
		return parseMainnetPayload(payload)
	case hrpZone:
		return parseZonePayload(payload)
	default:
		return TempoAddress{}, fmt.Errorf("%w: got %q, expected %q or %q", ErrInvalidHRP, hrp, hrpMainnet, hrpZone)
	}
}

// ValidateTempoAddress reports whether s is a valid Bech32m-encoded Tempo address.
func ValidateTempoAddress(s string) bool {
	_, err := ParseTempoAddress(s)
	return err == nil
}

// parseMainnetPayload decodes payload for a mainnet (non-zone) address.
// Expected: [0x00 version] [20 bytes address] = 21 bytes.
func parseMainnetPayload(payload []byte) (TempoAddress, error) {
	if len(payload) != 21 {
		return TempoAddress{}, fmt.Errorf("%w: mainnet payload must be 21 bytes, got %d", ErrInvalidPayload, len(payload))
	}
	if payload[0] != versionByte {
		return TempoAddress{}, fmt.Errorf("%w: %d", ErrInvalidVersion, payload[0])
	}
	var addr common.Address
	copy(addr[:], payload[1:21])
	return NewTempoAddress(addr), nil
}

// parseZonePayload decodes payload for a zone address.
// Expected: [0x00 version] [compact_size zone_id] [20 bytes address].
func parseZonePayload(payload []byte) (TempoAddress, error) {
	if len(payload) < 2 {
		return TempoAddress{}, fmt.Errorf("%w: zone payload too short", ErrInvalidPayload)
	}
	if payload[0] != versionByte {
		return TempoAddress{}, fmt.Errorf("%w: %d", ErrInvalidVersion, payload[0])
	}

	zoneID, consumed, err := decodeCompactSize(payload[1:])
	if err != nil {
		return TempoAddress{}, fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}

	addrStart := 1 + consumed
	if len(payload) != addrStart+20 {
		return TempoAddress{}, fmt.Errorf("%w: zone payload must be %d bytes, got %d", ErrInvalidPayload, addrStart+20, len(payload))
	}

	var addr common.Address
	copy(addr[:], payload[addrStart:])
	return NewZoneTempoAddress(addr, zoneID), nil
}

// encodeCompactSize encodes a uint64 using Bitcoin's CompactSize (varint) format.
//
//	0-252:          1 byte
//	253-65535:      0xFD + LE uint16
//	65536-2^32-1:   0xFE + LE uint32
//	>= 2^32:        0xFF + LE uint64
func encodeCompactSize(v uint64) []byte {
	switch {
	case v <= 252:
		return []byte{byte(v)}
	case v <= 0xFFFF:
		buf := make([]byte, 3)
		buf[0] = 0xFD
		binary.LittleEndian.PutUint16(buf[1:], uint16(v))
		return buf
	case v <= 0xFFFFFFFF:
		buf := make([]byte, 5)
		buf[0] = 0xFE
		binary.LittleEndian.PutUint32(buf[1:], uint32(v))
		return buf
	default:
		buf := make([]byte, 9)
		buf[0] = 0xFF
		binary.LittleEndian.PutUint64(buf[1:], v)
		return buf
	}
}

// decodeCompactSize decodes a CompactSize value from data.
// Returns the value, bytes consumed, and any error.
func decodeCompactSize(data []byte) (uint64, int, error) {
	if len(data) == 0 {
		return 0, 0, fmt.Errorf("empty compact size")
	}
	switch {
	case data[0] <= 252:
		return uint64(data[0]), 1, nil
	case data[0] == 0xFD:
		if len(data) < 3 {
			return 0, 0, fmt.Errorf("compact size 0xFD requires 3 bytes, got %d", len(data))
		}
		return uint64(binary.LittleEndian.Uint16(data[1:3])), 3, nil
	case data[0] == 0xFE:
		if len(data) < 5 {
			return 0, 0, fmt.Errorf("compact size 0xFE requires 5 bytes, got %d", len(data))
		}
		return uint64(binary.LittleEndian.Uint32(data[1:5])), 5, nil
	case data[0] == 0xFF:
		if len(data) < 9 {
			return 0, 0, fmt.Errorf("compact size 0xFF requires 9 bytes, got %d", len(data))
		}
		return binary.LittleEndian.Uint64(data[1:9]), 9, nil
	default:
		return 0, 0, fmt.Errorf("invalid compact size prefix: %d", data[0])
	}
}
