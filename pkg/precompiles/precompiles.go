// Package precompiles exposes the complete ABI of each precompile interface
// exported by the pinned tempo-contracts revision. ABI availability does not
// imply activation on a particular network or hardfork.
package precompiles

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"math/big"
	"slices"
	"sort"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/tempoxyz/tempo-go/pkg/transaction"
)

//go:embed contracts.json
var source []byte

type contract struct {
	ABI       json.RawMessage   `json:"abi"`
	Address   *common.Address   `json:"address"`
	Selectors map[string]string `json:"selectors"`
}

type export struct {
	Revision  string              `json:"revision"`
	Contracts map[string]contract `json:"contracts"`
}

var catalog = func() export {
	var parsed export
	if err := json.Unmarshal(source, &parsed); err != nil {
		panic(err)
	}
	return parsed
}()

var names = func() []string {
	names := make([]string, 0, len(catalog.Contracts))
	for name := range catalog.Contracts {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}()

// Revision returns the Rust source commit used to generate these ABIs.
func Revision() string { return catalog.Revision }

// Names returns every available interface name in sorted order.
func Names() []string { return slices.Clone(names) }

// ABI returns an independent ABI value containing functions, events and errors.
// Use its Pack/Unpack, EventByID and ErrorByID methods with the SDK RPC client.
func ABI(name string) (abi.ABI, error) {
	c, ok := catalog.Contracts[name]
	if !ok {
		return abi.ABI{}, fmt.Errorf("unknown Tempo interface %q", name)
	}
	return abi.JSON(bytes.NewReader(c.ABI))
}

// Address returns the fixed system address, if the interface has one. Token,
// channel-reserve and zone interfaces require a deployment-specific address.
func Address(name string) (common.Address, bool) {
	c, ok := catalog.Contracts[name]
	if !ok || c.Address == nil {
		return common.Address{}, false
	}
	return *c.Address, true
}

// Call encodes any interface function as a Tempo batch call. Supply the target
// explicitly so dynamic deployments and network-specific addresses are supported.
// Overloaded function names follow go-ethereum ABI naming (name, name0, ...).
func Call(name string, target common.Address, method string, args ...interface{}) (transaction.Call, error) {
	if method == "" {
		return transaction.Call{}, fmt.Errorf("method name must not be empty")
	}
	contract, err := ABI(name)
	if err != nil {
		return transaction.Call{}, err
	}
	data, err := contract.Pack(method, args...)
	if err != nil {
		return transaction.Call{}, err
	}
	return transaction.Call{To: &target, Value: new(big.Int), Data: data}, nil
}
