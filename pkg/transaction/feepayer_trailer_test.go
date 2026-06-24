package transaction

import (
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tempoxyz/tempo-go/pkg/signer"
)

// buildSignedTxEndingInMarker returns a WebAuthn-signed transaction whose serialized
// payload legitimately ends in the 0xfeefeefeefee marker bytes.
func buildSignedTxEndingInMarker(t *testing.T) (*Tx, string) {
	t.Helper()
	recipient := common.HexToAddress("0x2222222222222222222222222222222222222222")

	raw := make([]byte, 129)
	raw[0] = 0x02 // WebAuthn type prefix
	copy(raw[len(raw)-6:], []byte{0xfe, 0xef, 0xee, 0xfe, 0xef, 0xee})

	tx := New()
	tx.Gas = 21000
	tx.Calls = []Call{{To: &recipient, Value: nil, Data: []byte{}}}
	tx.Signature = &signer.SignatureEnvelope{Type: "webauthn", Raw: raw}

	serialized, err := Serialize(tx, nil)
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(serialized, "feefeefeefee"),
		"test setup: serialized tx should end in the marker bytes")
	return tx, serialized
}

// A legitimate transaction whose payload ends in the marker bytes must NOT be truncated.
func TestDeserializeDoesNotTruncateLegitMarkerSuffix(t *testing.T) {
	tx, serialized := buildSignedTxEndingInMarker(t)

	got, err := Deserialize(serialized)
	require.NoError(t, err, "valid tx ending in marker bytes must still parse")
	require.NotNil(t, got.Signature)
	assert.Equal(t, tx.Signature.Raw, got.Signature.Raw,
		"signature must survive the round trip intact")
}

// A genuine tempo.ts trailer (address + marker) must be stripped before decoding.
func TestDeserializeStripsGenuineFeePayerTrailer(t *testing.T) {
	recipient := common.HexToAddress("0x3333333333333333333333333333333333333333")
	tx := New()
	tx.Gas = 21000
	tx.Calls = []Call{{To: &recipient, Value: nil, Data: []byte{}}}

	serialized, err := Serialize(tx, nil)
	require.NoError(t, err)

	// Append <20-byte address> + marker, exactly as tempo.ts does.
	withTrailer := serialized + strings.Repeat("0", 40) + "feefeefeefee"

	got, err := Deserialize(withTrailer)
	require.NoError(t, err)
	assert.Equal(t, uint64(21000), got.Gas)
	require.Len(t, got.Calls, 1)
	assert.Equal(t, recipient, *got.Calls[0].To)
}
