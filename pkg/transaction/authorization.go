package transaction

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/tempoxyz/tempo-go/pkg/signer"
)

// SignedAuthorization is a Tempo EIP-7702 delegation. Unlike Ethereum's
// six-field authorization, Tempo encodes [chainId, address, nonce, signature]
// and permits any Tempo signature envelope.
type SignedAuthorization struct {
	ChainID   *big.Int                  `json:"chainId"`
	Address   common.Address            `json:"address"`
	Nonce     uint64                    `json:"nonce"`
	Signature *signer.SignatureEnvelope `json:"signature"`
}

// SignatureHash returns keccak256(0x05 || rlp([chainId, address, nonce])).
// Chain ID zero authorizes delegation on any chain, as in EIP-7702.
func (a SignedAuthorization) SignatureHash() (common.Hash, error) {
	if err := validateAuthorizationChainID(a.ChainID); err != nil {
		return common.Hash{}, err
	}
	payload, err := rlp.EncodeToBytes([]interface{}{a.ChainID, a.Address, a.Nonce})
	if err != nil {
		return common.Hash{}, err
	}
	return crypto.Keccak256Hash([]byte{0x05}, payload), nil
}

func validateAuthorizationChainID(chainID *big.Int) error {
	if chainID == nil || chainID.Sign() < 0 || chainID.BitLen() > 256 {
		return fmt.Errorf("authorization chain ID must be an unsigned 256-bit integer")
	}
	return nil
}

// Sign signs a delegation with a secp256k1 key. Other signers can set Signature
// directly after signing SignatureHash with their supported envelope format.
func (a *SignedAuthorization) Sign(s *signer.Signer) error {
	if s == nil {
		return fmt.Errorf("authorization signer is nil")
	}
	hash, err := a.SignatureHash()
	if err != nil {
		return err
	}
	sig, err := s.Sign(hash)
	if err != nil {
		return err
	}
	a.Signature = signer.NewSignatureEnvelope(sig.R, sig.S, sig.YParity)
	return nil
}

// Clone copies a delegation, retaining its independently signed authorization.
func (a SignedAuthorization) Clone() SignedAuthorization {
	a.ChainID = copyBigInt(a.ChainID)
	if a.Signature != nil {
		envelope := *a.Signature
		envelope.Raw = append([]byte(nil), envelope.Raw...)
		if envelope.Signature != nil {
			sig := *envelope.Signature
			sig.R, sig.S = copyBigInt(sig.R), copyBigInt(sig.S)
			envelope.Signature = &sig
		}
		a.Signature = &envelope
	}
	return a
}

func encodeAuthorizations(list []SignedAuthorization) ([]interface{}, error) {
	result := make([]interface{}, len(list))
	for i, auth := range list {
		if err := validateAuthorizationChainID(auth.ChainID); err != nil {
			return nil, fmt.Errorf("authorization %d: %w", i, err)
		}
		if auth.Signature == nil {
			return nil, fmt.Errorf("authorization %d: missing signature", i)
		}
		sig, err := encodeSignatureEnvelope(auth.Signature)
		if err != nil {
			return nil, fmt.Errorf("authorization %d: %w", i, err)
		}
		if len(sig) == 0 {
			return nil, fmt.Errorf("authorization %d: empty signature", i)
		}
		result[i] = []interface{}{auth.ChainID, auth.Address, auth.Nonce, sig}
	}
	return result, nil
}

func decodeAuthorizations(raw interface{}) ([]SignedAuthorization, error) {
	list, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("authorizationList must be an RLP list")
	}
	if len(list) == 0 {
		return nil, nil
	}
	result := make([]SignedAuthorization, len(list))
	for i, item := range list {
		fields, ok := item.([]interface{})
		if !ok || len(fields) != 4 {
			return nil, fmt.Errorf("authorization %d: expected four fields", i)
		}
		chain, ok := fields[0].([]byte)
		if !ok || len(chain) > 32 || (len(chain) > 0 && chain[0] == 0) {
			return nil, fmt.Errorf("authorization %d: invalid chain ID", i)
		}
		address, ok := fields[1].([]byte)
		if !ok || len(address) != common.AddressLength {
			return nil, fmt.Errorf("authorization %d: invalid address", i)
		}
		nonceBytes, ok := fields[2].([]byte)
		if !ok || (len(nonceBytes) > 0 && nonceBytes[0] == 0) {
			return nil, fmt.Errorf("authorization %d: invalid nonce", i)
		}
		nonce, err := bytesToUint64(nonceBytes)
		if err != nil {
			return nil, fmt.Errorf("authorization %d: invalid nonce: %w", i, err)
		}
		sig, ok := fields[3].([]byte)
		if !ok || len(sig) == 0 {
			return nil, fmt.Errorf("authorization %d: missing signature", i)
		}
		envelope, err := decodeSignatureEnvelope(sig)
		if err != nil {
			return nil, fmt.Errorf("authorization %d: %w", i, err)
		}
		result[i] = SignedAuthorization{ChainID: new(big.Int).SetBytes(chain), Address: common.BytesToAddress(address), Nonce: nonce, Signature: envelope}
	}
	return result, nil
}
