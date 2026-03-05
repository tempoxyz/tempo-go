package main

import (
	"fmt"
	"log"

	"github.com/ethereum/go-ethereum/common"
	"github.com/tempoxyz/tempo-go/pkg/address"
)

func main() {
	addr := common.HexToAddress("0x742d35CC6634c0532925a3B844bc9e7595F2Bd28")

	// Encode a mainnet address
	ta := address.NewTempoAddress(addr)
	fmt.Println("Mainnet:", ta)

	// Encode a zone address
	za := address.NewZoneTempoAddress(addr, 1)
	fmt.Println("Zone:   ", za)

	// Parse a Tempo address back to an Ethereum address
	parsed, err := address.ParseTempoAddress(ta.String())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Parsed: ", parsed.EthAddress().Hex())

	// Validate an address string
	fmt.Println("Valid:  ", address.ValidateTempoAddress(ta.String()))
}
