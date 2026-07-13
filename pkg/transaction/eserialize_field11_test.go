package transaction

import (
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A 0x76 transaction whose field 11 carries a bare (non-tuple, non-0x00) byte string
// is malformed and must be rejected rather than silently ignored.
func TestDeserializeRejectsMalformedField11(t *testing.T) {
	addr := make([]byte, 20)
	addr[0] = 0xab // a 20-byte sender address — only valid in the 0x78 signing form

	fields := []interface{}{
		[]byte{0x10},       // 0  chainId
		[]byte{},           // 1  maxPriorityFeePerGas
		[]byte{},           // 2  maxFeePerGas
		[]byte{0x52, 0x08}, // 3  gas
		[]interface{}{},    // 4  calls
		[]interface{}{},    // 5  accessList
		[]byte{},           // 6  nonceKey
		[]byte{},           // 7  nonce
		[]byte{},           // 8  validBefore
		[]byte{},           // 9  validAfter
		[]byte{},           // 10 feeToken
		addr,               // 11 feePayerSignatureOrSender (malformed)
		[]interface{}{},    // 12 authorizationList
	}

	rlpBytes, err := rlp.EncodeToBytes(fields)
	require.NoError(t, err)
	serialized := "0x76" + hex.EncodeToString(rlpBytes)

	_, err = Deserialize(serialized)
	require.Error(t, err, "malformed field 11 must be rejected")
	assert.Contains(t, err.Error(), "field 11")
}
