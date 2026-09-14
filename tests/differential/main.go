// Command differential runs local, valid-envelope codec comparisons using DFF.
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jtraglia/dff"
	"github.com/tempoxyz/tempo-go/pkg/keychain"
	"github.com/tempoxyz/tempo-go/pkg/signer"
	"github.com/tempoxyz/tempo-go/pkg/transaction"
)

func process(method string, inputs [][]byte) ([]byte, error) {
	method = strings.TrimRight(method, "\x00")
	if method != "tempo-codec" || len(inputs) != 1 {
		return nil, fmt.Errorf("invalid request")
	}
	tx, err := transaction.Deserialize(hex.EncodeToString(inputs[0]))
	if err != nil {
		return nil, err
	}
	raw, err := transaction.Serialize(tx, nil)
	if err != nil {
		return nil, err
	}
	result, err := hex.DecodeString(raw[2:])
	if err != nil {
		return nil, err
	}
	hash, err := transaction.GetSignPayload(tx)
	if err != nil {
		return nil, err
	}
	result = append(result, hash.Bytes()...)
	hash, err = transaction.GetFeePayerSignPayload(tx, common.BytesToAddress(bytes.Repeat([]byte{0x11}, 20)))
	if err != nil {
		return nil, err
	}
	result = append(result, hash.Bytes()...)
	for _, auth := range tx.AuthorizationList {
		hash, err = auth.SignatureHash()
		if err != nil {
			return nil, err
		}
		result = append(result, hash.Bytes()...)
	}
	return result, nil
}

// Generate codec-valid envelopes. Signature bytes are fixtures, not proof that
// a node would accept them: execution and cryptographic verification are separate.
func generate(seed int64) []byte {
	r := rand.New(rand.NewSource(seed))
	data := func(n int) []byte { b := make([]byte, n); _, _ = r.Read(b); return b }
	address := func() common.Address { return common.BytesToAddress(data(20)) }
	tx := transaction.NewDefault(4217)
	if seed%11 == 0 {
		tx.ChainID.SetUint64(0)
	}
	if seed%13 == 0 {
		tx.ChainID.SetUint64(^uint64(0))
	}
	tx.Gas, tx.Nonce = r.Uint64(), r.Uint64()
	tx.MaxFeePerGas.SetBytes(data(16))
	tx.MaxPriorityFeePerGas.SetBytes(data(16))
	tx.NonceKey.SetBytes(data(32))
	if seed%5 == 0 {
		tx.NonceKey.Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	}
	if seed%2 == 0 {
		tx.ValidAfter = r.Uint64() >> 1
		tx.ValidBefore = tx.ValidAfter + 1 + (r.Uint64() >> 1)
	}
	if seed%3 == 0 {
		tx.FeeToken = address()
	}
	if seed%3 == 1 {
		tx.FeeTokenSet = true
	}
	for i := 0; i < 1+r.Intn(4); i++ {
		to := address()
		tx.Calls = append(tx.Calls, transaction.Call{To: &to, Value: new(big.Int).SetBytes(data(32)), Data: data(r.Intn(257))})
	}
	if seed%7 == 0 {
		tx.Calls[0].To = nil
	}
	for i := 0; i < r.Intn(4); i++ {
		tx.AccessList = append(tx.AccessList, transaction.AccessTuple{Address: address(), StorageKeys: []common.Hash{common.BytesToHash(data(32))}})
	}
	primitive := func(kind int) *signer.SignatureEnvelope {
		switch kind {
		case 0:
			return signer.NewSignatureEnvelope(big.NewInt(1), big.NewInt(2), byte(r.Intn(2)))
		case 1:
			raw := append([]byte{1}, data(129)...)
			raw[129] = byte(r.Intn(2))
			return &signer.SignatureEnvelope{Type: "p256", Raw: raw}
		default:
			return &signer.SignatureEnvelope{Type: "webauthn", Raw: append([]byte{2}, data(128+r.Intn(1921))...)}
		}
	}
	tx.Signature = primitive(int(seed % 3))
	if seed%4 < 2 {
		inner := tx.Signature.Raw
		if inner == nil {
			inner = make([]byte, 65)
			inner[31] = 1
			inner[63] = 2
			inner[64] = tx.Signature.Signature.YParity
		}
		raw := append([]byte{byte(3 + seed%2)}, address().Bytes()...)
		tx.Signature = &signer.SignatureEnvelope{Type: "keychain", Raw: append(raw, inner...)}
	}
	if seed%2 == 0 {
		tx.FeePayerSignature = signer.NewSignature(big.NewInt(3), big.NewInt(4), byte(r.Intn(2)))
	}
	if tx.Calls[0].To != nil {
		for i := 0; i < int(seed%4); i++ {
			tx.AuthorizationList = append(tx.AuthorizationList, transaction.SignedAuthorization{ChainID: new(big.Int).SetBytes(data(32)), Address: address(), Nonce: r.Uint64(), Signature: primitive(i % 3)})
		}
	}
	if seed%3 != 0 {
		auth := keychain.NewKeyAuthorization(4217, uint8(seed%3), address())
		if seed%2 == 0 {
			auth.WithExpiry(r.Uint64()).WithNoSpending().WithNoCalls()
		}
		if seed%5 == 0 {
			auth.WithWitness(common.BytesToHash(data(32))).WithAccount(address())
		}
		sig := make([]byte, 65)
		sig[31] = 1
		sig[63] = 2
		sig[64] = 27
		var err error
		tx.KeyAuthorization, err = auth.BuildSigned(sig)
		if err != nil {
			panic(err)
		}
	}
	raw, err := transaction.Serialize(tx, nil)
	if err != nil {
		panic(err)
	}
	encoded, err := hex.DecodeString(raw[2:])
	if err != nil {
		panic(err)
	}
	return encoded
}

func main() {
	role := flag.String("role", "go", "go, server, corpus, or replay")
	seed := flag.Int64("seed", 1, "first reproducible case seed")
	count := flag.Int("count", 1000, "number of corpus cases")
	flag.Parse()
	if *seed < 0 || *count < 1 {
		log.Fatal("seed must be nonnegative and count positive")
	}
	switch *role {
	case "corpus":
		for i := 0; i < *count; i++ {
			fmt.Printf("%x\n", generate(*seed+int64(i)))
		}
	case "replay":
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			input, err := hex.DecodeString(scanner.Text())
			if err != nil {
				log.Fatal(err)
			}
			output, err := process("tempo-codec", [][]byte{input})
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("%x\n", output)
		}
		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		}
	case "server":
		ready := false
		// The pinned Rust client reads exactly 64 method bytes; the Go server
		// sends the supplied string verbatim. Pad it to bridge those contracts.
		method := "tempo-codec" + strings.Repeat("\x00", 64-len("tempo-codec"))
		s := dff.NewServer(method, func() [][]byte {
			if !ready {
				deadline := time.Now().Add(30 * time.Second)
				for {
					_, goErr := os.Stat("go.ready")
					_, rustErr := os.Stat("rust.ready")
					if goErr == nil && rustErr == nil {
						ready = true
						break
					}
					if time.Now().After(deadline) {
						log.Fatal("both clients must register before comparison")
					}
					time.Sleep(10 * time.Millisecond)
				}
			}
			input := generate(*seed)
			*seed++
			return [][]byte{input}
		})
		if err := s.Start(); err != nil {
			log.Fatal(err)
		}
	case "go":
		c := dff.NewClient("go", process)
		if err := c.Connect(); err != nil {
			log.Fatal(err)
		}
		defer c.Close()
		if err := os.WriteFile("go.ready", []byte("ready"), 0600); err != nil {
			log.Fatal(err)
		}
		if err := c.Run(); err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatal("unknown role")
	}
}
