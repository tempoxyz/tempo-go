package transaction

import (
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
)

// Real AgentCash-signed Tempo MPP transaction captured 2026-06-03 against the
// skills.onesource.io tempo "charge" challenge (USDC.e, chainId 4217).
// Its 65-byte secp256k1 signature envelope ends in 0x1c (recovery id 28) — the
// pre-EIP-155 legacy convention. Before this change tempo-go rejected it with:
//
//	failed to decode signature envelope: invalid yParity in signature envelope:
//	must be 0 or 1, got 28
//
// Signer (source) address from the captured DID did:pkh:eip155:4217:0x33b26E11...
const agentCashRealTx = "0x76f8fd8210798085059682f000830118f0f87ef87c9420c000000000000000000000b9537d11c60e8b5080b86495777d5900000000000000000000000019b8e99079a5558ff4460357b0a78e14a7f600b700000000000000000000000000000000000000000000000000000000000003e8ef1ed71201b1f7cc04955c6f30483800000000000000000000485f76c6fe43f8c0a0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80846a204591808080c0b84197319b351c967f72ffacf2b7312077cd9aa2e33ee0ee8c656e9807750006c0c3685c66ab8ddad86fba696a8d88f11784c69d28bb8259c25790283d3c4a1e96b51c"

const agentCashSigner = "0x33b26E111fC756887edcc2C85862056378dcfD8c"

func TestDeserialize_AgentCashRealLegacyRecoveryID(t *testing.T) {
	// envelope must really end in 0x1c (28) for this to be the regression case.
	assert.True(t, strings.HasSuffix(agentCashRealTx, "1c"), "captured tx should end in legacy recovery id 0x1c")

	tx, err := Deserialize(agentCashRealTx)
	assert.NoError(t, err, "legacy {27,28} recovery id in 65-byte envelope must deserialize")
	assert.NotNil(t, tx)
	assert.NotNil(t, tx.Signature)

	recovered, err := VerifySignature(tx)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToAddress(agentCashSigner), recovered, "must recover the AgentCash signer address")
}
