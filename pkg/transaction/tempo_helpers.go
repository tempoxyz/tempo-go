package transaction

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	// TIP20TransferSelector is the transfer(address,uint256) selector without a 0x prefix.
	TIP20TransferSelector = "a9059cbb"
	// TIP20ApproveSelector is the approve(address,uint256) selector without a 0x prefix.
	TIP20ApproveSelector = "095ea7b3"
	// TIP20TransferWithMemoSelector is the transferWithMemo(address,uint256,bytes32) selector without a 0x prefix.
	TIP20TransferWithMemoSelector = "95777d59"
	tip20SelectorSize             = 4
	tip20ABISlotSize              = 32
	tip20TransferCalldataSize     = tip20SelectorSize + (2 * tip20ABISlotSize)
	tip20TransferWithMemoDataSize = tip20SelectorSize + (3 * tip20ABISlotSize)
	tip20AddressOffset            = tip20SelectorSize + tip20ABISlotSize - common.AddressLength
	tip20AmountOffset             = tip20SelectorSize + tip20ABISlotSize
	tip20MemoOffset               = tip20AmountOffset + tip20ABISlotSize
)

// Common Tempo token and precompile addresses.
var (
	// PathUSDAddress is Tempo's native fee token address.
	PathUSDAddress = common.HexToAddress("0x20c0000000000000000000000000000000000000")
	// FeeManagerAddress is the fee manager precompile.
	FeeManagerAddress = common.HexToAddress("0xfeec000000000000000000000000000000000000")
	// StablecoinDEXAddress is the stablecoin DEX precompile.
	StablecoinDEXAddress = common.HexToAddress("0xdec0000000000000000000000000000000000000")
	// AccountKeychainAddress is the account keychain precompile.
	AccountKeychainAddress = common.HexToAddress("0xaaaaaaaa00000000000000000000000000000000")
	// TIP20TransferTopic is the Transfer(address,address,uint256) event topic.
	TIP20TransferTopic = crypto.Keccak256Hash([]byte("Transfer(address,address,uint256)"))
	// TIP20TransferWithMemoTopic is the TransferWithMemo(address,address,uint256,bytes32) event topic.
	TIP20TransferWithMemoTopic = crypto.Keccak256Hash([]byte("TransferWithMemo(address,address,uint256,bytes32)"))
)

var (
	tip20TransferSelectorBytes         = [4]byte{0xa9, 0x05, 0x9c, 0xbb}
	tip20TransferWithMemoSelectorBytes = [4]byte{0x95, 0x77, 0x7d, 0x59}
)

// EncodeTIP20TransferData encodes TIP-20 transfer(address,uint256) calldata.
func EncodeTIP20TransferData(recipient common.Address, amount *big.Int) ([]byte, error) {
	data := make([]byte, tip20TransferCalldataSize)
	copy(data[:tip20SelectorSize], tip20TransferSelectorBytes[:])
	copy(data[tip20AddressOffset:tip20AmountOffset], recipient.Bytes())
	if err := encodeUint256(amount, data[tip20AmountOffset:tip20TransferCalldataSize]); err != nil {
		return nil, err
	}
	return data, nil
}

// EncodeTIP20TransferWithMemoData encodes TIP-20 transferWithMemo(address,uint256,bytes32) calldata.
func EncodeTIP20TransferWithMemoData(recipient common.Address, amount *big.Int, memo []byte) ([]byte, error) {
	if len(memo) != tip20ABISlotSize {
		return nil, fmt.Errorf("memo must be exactly 32 bytes")
	}
	data := make([]byte, tip20TransferWithMemoDataSize)
	copy(data[:tip20SelectorSize], tip20TransferWithMemoSelectorBytes[:])
	copy(data[tip20AddressOffset:tip20AmountOffset], recipient.Bytes())
	if err := encodeUint256(amount, data[tip20AmountOffset:tip20MemoOffset]); err != nil {
		return nil, err
	}
	copy(data[tip20MemoOffset:tip20TransferWithMemoDataSize], memo)
	return data, nil
}

// ParseTopicAddress extracts the indexed address stored in an event topic.
// Invalid topics return the zero address.
func ParseTopicAddress(topic string) common.Address {
	trimmed := strings.TrimPrefix(strings.TrimPrefix(topic, "0x"), "0X")
	if len(trimmed) != common.HashLength*2 {
		return common.Address{}
	}
	topicBytes, err := hex.DecodeString(trimmed)
	if err != nil {
		return common.Address{}
	}
	return common.BytesToAddress(topicBytes[common.HashLength-common.AddressLength:])
}

func encodeUint256(value *big.Int, dst []byte) error {
	if value == nil {
		return nil
	}
	if value.Sign() < 0 {
		return fmt.Errorf("amount must be non-negative")
	}
	if value.BitLen() > 256 {
		return fmt.Errorf("amount exceeds uint256")
	}
	value.FillBytes(dst)
	return nil
}
