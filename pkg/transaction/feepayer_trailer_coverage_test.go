package transaction

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeserializeRejectsTrailerOnSponsoredTransaction(t *testing.T) {
	recipient := common.HexToAddress("0x4444444444444444444444444444444444444444")
	tx := New()
	tx.Gas = 21000
	tx.FeeToken = AlphaUSDAddress
	tx.AwaitingFeePayer = true
	tx.Calls = []Call{{To: &recipient, Value: nil, Data: []byte{0x01, 0x02}}}

	serialized, err := Serialize(tx, nil)
	require.NoError(t, err)

	_, err = Deserialize(serialized + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + "feefeefeefee")
	require.Error(t, err)
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
