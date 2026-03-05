package address_test

import (
	"fmt"
	"log"

	"github.com/ethereum/go-ethereum/common"
	"github.com/tempoxyz/tempo-go/pkg/address"
)

// Example_mainnetAddress demonstrates creating and formatting a mainnet TempoAddress.
func Example_mainnetAddress() {
	addr := common.HexToAddress("0x742d35CC6634c0532925a3B844bc9e7595F2Bd28")
	ta := address.NewTempoAddress(addr)

	fmt.Println(ta)

	// Output:
	// tempo1qp6z6dwvvc6vq5efyk3ms39une6etu4a9qtj2kk0
}

// Example_zoneAddress demonstrates creating a zone TempoAddress.
func Example_zoneAddress() {
	addr := common.HexToAddress("0x742d35CC6634c0532925a3B844bc9e7595F2Bd28")
	ta := address.NewZoneTempoAddress(addr, 1)

	fmt.Println(ta.Format())

	// Output:
	// tempoz1qqqhgtf4e3nrfszn9yj68wzyhj08t90jh55q74d9uj
}

// Example_parseAndValidate demonstrates parsing and validating a TempoAddress string.
func Example_parseAndValidate() {
	s := "tempo1qp6z6dwvvc6vq5efyk3ms39une6etu4a9qtj2kk0"

	parsed, err := address.ParseTempoAddress(s)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Eth address:", parsed.EthAddress().Hex())
	fmt.Println("Valid:", address.ValidateTempoAddress(s))

	// Output:
	// Eth address: 0x742d35CC6634c0532925a3B844bc9e7595F2Bd28
	// Valid: true
}
