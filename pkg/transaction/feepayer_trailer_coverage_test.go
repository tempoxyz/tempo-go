package transaction

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeserializeStripsTrailerWithoutChangingSponsoredTransaction(t *testing.T) {
	recipient := common.HexToAddress("0x4444444444444444444444444444444444444444")
	tx := New()
	tx.Gas = 21000
	tx.FeeToken = AlphaUSDAddress
	tx.AwaitingFeePayer = true
	tx.Calls = []Call{{To: &recipient, Value: nil, Data: []byte{0x01, 0x02}}}

	serialized, err := Serialize(tx, nil)
	require.NoError(t, err)
	withTrailer := serialized + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + "feefeefeefee"

	got, err := Deserialize(withTrailer)
	require.NoError(t, err)
	assert.True(t, got.AwaitingFeePayer)
	assert.Equal(t, AlphaUSDAddress, got.FeeToken)
	require.Len(t, got.Calls, 1)
	assert.Equal(t, []byte{0x01, 0x02}, got.Calls[0].Data)
}

func TestDeserializePreservesCallDataEndingInFeePayerMarker(t *testing.T) {
	recipient := common.HexToAddress("0x5555555555555555555555555555555555555555")
	marker := []byte{0xfe, 0xef, 0xee, 0xfe, 0xef, 0xee}
	tx := New()
	tx.Gas = 21000
	tx.Calls = []Call{{To: &recipient, Value: nil, Data: append([]byte{0x01, 0x02}, marker...)}}

	serialized, err := Serialize(tx, nil)
	require.NoError(t, err)

	got, err := Deserialize(serialized)
	require.NoError(t, err)
	require.Len(t, got.Calls, 1)
	assert.Equal(t, tx.Calls[0].Data, got.Calls[0].Data)
}
