package transaction

import (
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
	// MainnetUSDCAddressHex is Circle's USDC contract on Tempo mainnet.
	MainnetUSDCAddressHex = "0x20C000000000000000000000b9537d11c60E8b50"
)

// Common Tempo token and precompile addresses.
var (
	// PathUSDAddress is Tempo's native fee token address.
	PathUSDAddress = common.HexToAddress("0x20c0000000000000000000000000000000000000")
	// BetaUSDAddress is the BetaUSD token address.
	BetaUSDAddress = common.HexToAddress("0x20c0000000000000000000000000000000000002")
	// ThetaUSDAddress is the ThetaUSD token address.
	ThetaUSDAddress = common.HexToAddress("0x20c0000000000000000000000000000000000003")
	// MainnetUSDCAddress is Circle's USDC contract on Tempo mainnet.
	MainnetUSDCAddress = common.HexToAddress(MainnetUSDCAddressHex)
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
func EncodeTIP20TransferData(recipient common.Address, amount *big.Int) []byte {
	data := make([]byte, 4+32+32)
	copy(data[:4], tip20TransferSelectorBytes[:])
	copy(data[16:36], recipient.Bytes())
	if amount != nil {
		amount.FillBytes(data[36:68])
	}
	return data
}

// EncodeTIP20TransferWithMemoData encodes TIP-20 transferWithMemo(address,uint256,bytes32) calldata.
func EncodeTIP20TransferWithMemoData(recipient common.Address, amount *big.Int, memo []byte) ([]byte, error) {
	if len(memo) != 32 {
		return nil, fmt.Errorf("memo must be exactly 32 bytes")
	}
	data := make([]byte, 4+32+32+32)
	copy(data[:4], tip20TransferWithMemoSelectorBytes[:])
	copy(data[16:36], recipient.Bytes())
	if amount != nil {
		amount.FillBytes(data[36:68])
	}
	copy(data[68:100], memo)
	return data, nil
}

// ParseTopicAddress extracts the indexed address stored in an event topic.
// Invalid topics return the zero address.
func ParseTopicAddress(topic string) common.Address {
	trimmed := strings.TrimPrefix(strings.ToLower(topic), "0x")
	if len(trimmed) < 40 {
		return common.Address{}
	}
	return common.HexToAddress("0x" + trimmed[len(trimmed)-40:])
}
