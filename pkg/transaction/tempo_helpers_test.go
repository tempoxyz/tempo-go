package transaction

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncodeTIP20TransferData(t *testing.T) {
	recipient := common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	amount := big.NewInt(123456789)

	data := EncodeTIP20TransferData(recipient, amount)

	assert.Equal(t, TIP20TransferSelector, hex.EncodeToString(data[:4]))
	assert.Len(t, data, 68)
	assert.Equal(t, recipient.Bytes(), data[16:36])
	assert.Equal(t, amount.Bytes(), bytesTrimLeftZero(data[36:68]))
}

func TestEncodeTIP20TransferWithMemoData(t *testing.T) {
	recipient := common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	amount := big.NewInt(42)
	memo := common.FromHex("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	data, err := EncodeTIP20TransferWithMemoData(recipient, amount, memo)
	require.NoError(t, err)

	assert.Equal(t, TIP20TransferWithMemoSelector, hex.EncodeToString(data[:4]))
	assert.Len(t, data, 100)
	assert.Equal(t, recipient.Bytes(), data[16:36])
	assert.Equal(t, amount.Bytes(), bytesTrimLeftZero(data[36:68]))
	assert.Equal(t, memo, data[68:100])
}

func TestEncodeTIP20TransferWithMemoDataRejectsBadMemoLength(t *testing.T) {
	_, err := EncodeTIP20TransferWithMemoData(common.Address{}, big.NewInt(1), []byte{0x01, 0x02})

	assert.EqualError(t, err, "memo must be exactly 32 bytes")
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
}

func TestTempoAddressConstants(t *testing.T) {
	assert.Equal(t, common.HexToAddress("0x20C000000000000000000000b9537d11c60E8b50"), MainnetUSDCAddress)
	assert.Equal(t, common.HexToAddress("0x20c0000000000000000000000000000000000000"), PathUSDAddress)
	assert.Equal(t, common.HexToAddress("0x20c0000000000000000000000000000000000002"), BetaUSDAddress)
	assert.Equal(t, common.HexToAddress("0x20c0000000000000000000000000000000000003"), ThetaUSDAddress)
}

func bytesTrimLeftZero(input []byte) []byte {
	trimmed := input
	for len(trimmed) > 1 && trimmed[0] == 0 {
		trimmed = trimmed[1:]
	}
	return trimmed
}
