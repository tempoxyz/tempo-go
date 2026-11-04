package transaction

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/google/go-cmp/cmp"
)

// cmpOpts are options for comparing transactions with go-cmp.
// Includes a custom comparer for *big.Int since they need special comparison.
var cmpOpts = []cmp.Option{
	cmp.Comparer(func(x, y *big.Int) bool {
		if x == nil && y == nil {
			return true
		}
		if x == nil || y == nil {
			return false
		}
		return x.Cmp(y) == 0
	}),
}

// addrPtr is a test helper that returns a pointer to a common.Address.
func addrPtr(addr common.Address) *common.Address {
	return &addr
}
