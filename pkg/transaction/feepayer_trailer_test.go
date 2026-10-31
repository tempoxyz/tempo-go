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

// The legacy tempo.ts fee-payer format (RLP || 20-byte sender || 0xfeefeefeefee) is
// rejected, as the node rejects it.
func TestDeserializeRejectsLegacyFeePayerTrailer(t *testing.T) {
	recipient := common.HexToAddress("0x3333333333333333333333333333333333333333")
	tx := New()
	tx.Gas = 21000
	tx.Calls = []Call{{To: &recipient, Value: nil, Data: []byte{}}}

	serialized, err := Serialize(tx, nil)
	require.NoError(t, err)

	_, err = Deserialize(serialized + strings.Repeat("0", 40) + "feefeefeefee")
	require.Error(t, err)
}

// A transaction tempo.ts signed in the legacy fee-payer format (formerly a golden
// vector here) is rejected.
func TestDeserializeRejectsTempoTsFeePayerGolden(t *testing.T) {
	clientTx := "0x76f87582a5bd808502cb417800825dc2dcdb9400000000000000000000000000000000000000008084deadbeefc0800b80808000c0b8417607a2e7bea757dc38093db971a7ec7537a690a698119d629b2eb6bb433315767a20aeb717b10285986bc22f0cbb7e9254a2a1f35d5c29ad5119e8b46e202ec401d47b37BBC34fa57e9a67Ae7d0a1496edC88f04Bbfeefeefeefee"
	_, err := Deserialize(clientTx)
	require.Error(t, err)
}
