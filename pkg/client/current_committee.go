package client

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
)

// CurrentCommitteeAddress is the address of the T8 CurrentCommittee precompile.
const CurrentCommitteeAddress = "0xC077E00000000000000000000000000000000000"

// GetCommitteeMembersSelector is the selector for getCommitteeMembers().
const GetCommitteeMembersSelector = "0xb2a275f9"

var currentCommitteeABI = mustParseCurrentCommitteeABI(`[{
	"name": "getCommitteeMembers",
	"type": "function",
	"stateMutability": "view",
	"inputs": [],
	"outputs": [
		{"name": "epoch", "type": "uint64"},
		{"name": "publicKeys", "type": "bytes32[]"}
	]
}]`)

func mustParseCurrentCommitteeABI(json string) abi.ABI {
	parsed, err := abi.JSON(strings.NewReader(json))
	if err != nil {
		panic(fmt.Sprintf("failed to parse CurrentCommittee ABI: %v", err))
	}
	return parsed
}

// GetCommitteeMembers returns the effective validator committee for the
// current epoch. The public keys are ordered as selected by the DKG outcome.
func (c *Client) GetCommitteeMembers(ctx context.Context) (epoch uint64, publicKeys [][32]byte, err error) {
	callObject := map[string]string{
		"to":   CurrentCommitteeAddress,
		"data": GetCommitteeMembersSelector,
	}

	response, err := c.SendRequest(ctx, "eth_call", callObject, "latest")
	if err != nil {
		return 0, nil, err
	}
	if err := response.CheckError(); err != nil {
		return 0, nil, err
	}

	resultHex, ok := response.Result.(string)
	if !ok {
		return 0, nil, fmt.Errorf("unexpected result type: %T", response.Result)
	}
	result, err := hex.DecodeString(strings.TrimPrefix(resultHex, "0x"))
	if err != nil {
		return 0, nil, fmt.Errorf("failed to decode getCommitteeMembers result: %w", err)
	}

	values, err := currentCommitteeABI.Unpack("getCommitteeMembers", result)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to decode getCommitteeMembers result: %w", err)
	}
	if len(values) != 2 {
		return 0, nil, fmt.Errorf("expected 2 return values, got %d", len(values))
	}

	epoch, ok = values[0].(uint64)
	if !ok {
		return 0, nil, fmt.Errorf("unexpected epoch type: %T", values[0])
	}
	publicKeys, ok = values[1].([][32]byte)
	if !ok {
		return 0, nil, fmt.Errorf("unexpected public keys type: %T", values[1])
	}
	return epoch, publicKeys, nil
}
