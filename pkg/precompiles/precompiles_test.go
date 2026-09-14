package precompiles

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

func TestNamesReturnsCopy(t *testing.T) {
	names := Names()
	names[0] = "mutated"
	require.NotEqual(t, "mutated", Names()[0])
}

func TestRustSelectors(t *testing.T) {
	require.Len(t, Names(), 19)
	for _, name := range Names() {
		contract, err := ABI(name)
		require.NoError(t, err, name)
		require.Len(t, contract.Methods, len(catalog.Contracts[name].Selectors), name)
		for _, method := range contract.Methods {
			require.Equal(t, catalog.Contracts[name].Selectors[method.Sig], hex.EncodeToString(method.ID), name+"."+method.Sig)
		}
	}
	_, err := ABI("missing")
	require.Error(t, err)
}

func TestCall(t *testing.T) {
	target := common.HexToAddress("0x20c0000000000000000000000000000000000000")
	recipient := common.HexToAddress("0x1234")
	call, err := Call("ITIP20", target, "transfer", recipient, big.NewInt(42))
	require.NoError(t, err)
	require.Equal(t, target, *call.To)
	require.Equal(t, "a9059cbb", hex.EncodeToString(call.Data[:4]))
	require.Len(t, call.Data, 68)
	require.Zero(t, call.Value.Sign())

	_, err = Call("ITIP20", target, "")
	require.Error(t, err)
	_, err = Call("missing", target, "transfer")
	require.Error(t, err)
}

func TestAddress(t *testing.T) {
	_, fixed := Address("ITIP20")
	require.False(t, fixed)
	address, fixed := Address("INonce")
	require.True(t, fixed)
	require.Equal(t, common.HexToAddress("0x4E4F4E4345000000000000000000000000000000"), address)
}
