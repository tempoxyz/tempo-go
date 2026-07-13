package transaction

import (
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeserializeRejectsMalformedField11Lists(t *testing.T) {
	invalidLists := []struct {
		name  string
		value []interface{}
	}{
		{name: "empty", value: []interface{}{}},
		{name: "one item", value: []interface{}{[]byte{0x00}}},
		{name: "two items", value: []interface{}{[]byte{0x00}, []byte{0x01}}},
		{name: "four items", value: []interface{}{[]byte{0x00}, []byte{0x01}, []byte{0x02}, []byte{0x03}}},
	}

	for _, tc := range invalidLists {
		t.Run(tc.name, func(t *testing.T) {
			fields := []interface{}{
				[]byte{0x10}, []byte{}, []byte{}, []byte{0x52, 0x08},
				[]interface{}{}, []interface{}{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{},
				tc.value,
				[]interface{}{},
			}
			raw, err := rlp.EncodeToBytes(fields)
			require.NoError(t, err)

			_, err = Deserialize("0x76" + hex.EncodeToString(raw))
			require.Error(t, err, "field 11 %s list must be rejected", tc.name)
			assert.Contains(t, err.Error(), "field 11")
		})
	}
}
