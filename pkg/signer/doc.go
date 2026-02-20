// Package signer provides ECDSA signing utilities for Tempo transactions.
//
// This package wraps go-ethereum's crypto functions to provide a simple interface
// for signing transactions and messages with secp256k1 private keys.
//
// # Basic Usage
//
// Create a signer from a private key:
//
//	signer, err := signer.NewSigner("0x1234...")
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Get the address
//	address := signer.Address()
//	fmt.Printf("Address: %s\n", address.Hex())
//
// Sign data:
//
//	data := []byte("hello world")
//	signature, err := signer.SignData(data)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// signature contains r, s, and v values
//	fmt.Printf("R: %s\n", signature.R.String())
//	fmt.Printf("S: %s\n", signature.S.String())
//	fmt.Printf("YParity: %d\n", signature.YParity)
package signer
