package transaction

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var tip20TestABI = mustParseTIP20ABI()

func mustParseTIP20ABI() abi.ABI {
	parsed, err := abi.JSON(strings.NewReader(`[
		{"type":"function","name":"transfer","inputs":[{"name":"recipient","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[]},
		{"type":"function","name":"transferWithMemo","inputs":[{"name":"recipient","type":"address"},{"name":"amount","type":"uint256"},{"name":"memo","type":"bytes32"}],"outputs":[]}
	]`))
	if err != nil {
		panic(err)
	}
	return parsed
}

func TestEncodeTIP20TransferData(t *testing.T) {
	recipient := common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	amount := big.NewInt(123456789)

	data, err := EncodeTIP20TransferData(recipient, amount)
	require.NoError(t, err)

	assert.Equal(t, TIP20TransferSelector, hex.EncodeToString(data[:tip20SelectorSize]))
	assert.Len(t, data, tip20TransferCalldataSize)
	assert.Equal(t, recipient.Bytes(), data[tip20AddressOffset:tip20AmountOffset])
	assert.Equal(t, amount.Bytes(), bytesTrimLeftZero(data[tip20AmountOffset:tip20TransferCalldataSize]))
}

func TestEncodeTIP20TransferDataRejectsOutOfRangeAmount(t *testing.T) {
	_, err := EncodeTIP20TransferData(common.Address{}, new(big.Int).Lsh(big.NewInt(1), 256))

	assert.EqualError(t, err, "amount exceeds uint256")
}

func TestEncodeTIP20TransferWithMemoData(t *testing.T) {
	recipient := common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	amount := big.NewInt(42)
	memo := common.FromHex("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	data, err := EncodeTIP20TransferWithMemoData(recipient, amount, memo)
	require.NoError(t, err)

	assert.Equal(t, TIP20TransferWithMemoSelector, hex.EncodeToString(data[:tip20SelectorSize]))
	assert.Len(t, data, tip20TransferWithMemoDataSize)
	assert.Equal(t, recipient.Bytes(), data[tip20AddressOffset:tip20AmountOffset])
	assert.Equal(t, amount.Bytes(), bytesTrimLeftZero(data[tip20AmountOffset:tip20MemoOffset]))
	assert.Equal(t, memo, data[tip20MemoOffset:tip20TransferWithMemoDataSize])
}

func TestEncodeTIP20TransferWithMemoDataRejectsBadMemoLength(t *testing.T) {
	_, err := EncodeTIP20TransferWithMemoData(common.Address{}, big.NewInt(1), []byte{0x01, 0x02})

	assert.EqualError(t, err, "memo must be exactly 32 bytes")
}

func TestEncodeTIP20TransferWithMemoDataRejectsOutOfRangeAmount(t *testing.T) {
	_, err := EncodeTIP20TransferWithMemoData(common.Address{}, new(big.Int).Lsh(big.NewInt(1), 256), make([]byte, 32))

	assert.EqualError(t, err, "amount exceeds uint256")
}

func TestParseTopicAddress(t *testing.T) {
	t.Run("extracts indexed address", func(t *testing.T) {
		topic := "0x00000000000000000000000070997970C51812dc3A010C7d01b50e0d17dc79C8"

		address := ParseTopicAddress(topic)

		assert.Equal(t, common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8"), address)
	})

	t.Run("invalid topic returns zero address", func(t *testing.T) {
		assert.Equal(t, common.Address{}, ParseTopicAddress("0x1234"))
	})

	t.Run("non-hex topic returns zero address", func(t *testing.T) {
		assert.Equal(t, common.Address{}, ParseTopicAddress("0xzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"))
	})
}

func TestTempoAddressConstants(t *testing.T) {
	assert.Equal(t, common.HexToAddress("0x20c0000000000000000000000000000000000000"), PathUSDAddress)
}

func bytesTrimLeftZero(input []byte) []byte {
	trimmed := input
	for len(trimmed) > 1 && trimmed[0] == 0 {
		trimmed = trimmed[1:]
	}
	return trimmed
}

func FuzzEncodeTIP20TransferData(f *testing.F) {
	f.Add([]byte{0x01, 0x02, 0x03}, []byte{0x2a})
	f.Add(make([]byte, 20), []byte{})

	f.Fuzz(func(t *testing.T, addressBytes, amountBytes []byte) {
		var recipient common.Address
		if len(addressBytes) >= 20 {
			copy(recipient[:], addressBytes[:20])
		} else if len(addressBytes) > 0 {
			copy(recipient[20-len(addressBytes):], addressBytes)
		}

		amount := new(big.Int).SetBytes(amountBytes)
		data, err := EncodeTIP20TransferData(recipient, amount)
		if amount.BitLen() > 256 {
			if err == nil {
				t.Fatal("expected error for out-of-range amount")
			}
			return
		}
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expected, err := tip20TestABI.Pack("transfer", recipient, amount)
		if err != nil {
			t.Fatalf("unexpected abi pack error: %v", err)
		}
		if !bytes.Equal(data, expected) {
			t.Fatalf("encoded calldata mismatch: got %x want %x", data, expected)
		}
	})
}

func FuzzEncodeTIP20TransferWithMemoData(f *testing.F) {
	f.Add([]byte{0x01, 0x02, 0x03}, []byte{0x2a}, make([]byte, 32))
	f.Add(make([]byte, 20), []byte{}, []byte{0x01})

	f.Fuzz(func(t *testing.T, addressBytes, amountBytes, memo []byte) {
		var recipient common.Address
		if len(addressBytes) >= 20 {
			copy(recipient[:], addressBytes[:20])
		} else if len(addressBytes) > 0 {
			copy(recipient[20-len(addressBytes):], addressBytes)
		}

		amount := new(big.Int).SetBytes(amountBytes)
		data, err := EncodeTIP20TransferWithMemoData(recipient, amount, memo)
		if amount.BitLen() > 256 {
			if err == nil {
				t.Fatal("expected error for out-of-range amount")
			}
			return
		}
		if len(memo) != 32 {
			if err == nil {
				t.Fatal("expected error for invalid memo length")
			}
			return
		}
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var memoWord [32]byte
		copy(memoWord[:], memo)
		expected, err := tip20TestABI.Pack("transferWithMemo", recipient, amount, memoWord)
		if err != nil {
			t.Fatalf("unexpected abi pack error: %v", err)
		}
		if !bytes.Equal(data, expected) {
			t.Fatalf("encoded calldata mismatch: got %x want %x", data, expected)
		}
	})
}

func FuzzParseTopicAddress(f *testing.F) {
	f.Add([]byte{0x70, 0x99, 0x79, 0x70, 0xc5, 0x18, 0x12, 0xdc, 0x3a, 0x01, 0x0c, 0x7d, 0x01, 0xb5, 0x0e, 0x0d, 0x17, 0xdc, 0x79, 0xc8}, true, false)
	f.Add(make([]byte, 20), true, true)
	f.Add([]byte{0x01}, false, false)

	f.Fuzz(func(t *testing.T, addressBytes []byte, withPrefix, uppercase bool) {
		var expected common.Address
		if len(addressBytes) >= common.AddressLength {
			copy(expected[:], addressBytes[:common.AddressLength])
		} else if len(addressBytes) > 0 {
			copy(expected[common.AddressLength-len(addressBytes):], addressBytes)
		}

		var topic [common.HashLength]byte
		copy(topic[common.HashLength-common.AddressLength:], expected[:])

		topicHex := hex.EncodeToString(topic[:])
		if uppercase {
			topicHex = strings.ToUpper(topicHex)
		}
		if withPrefix {
			topicHex = "0x" + topicHex
		}

		parsed := ParseTopicAddress(topicHex)
		if parsed != expected {
			t.Fatalf("parsed address mismatch: got %s want %s", parsed.Hex(), expected.Hex())
		}
	})
}
