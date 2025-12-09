package main

import (
	"log"

	"github.com/tempoxyz/tempo-go/examples/feepayer/server"
	"github.com/tempoxyz/tempo-go/pkg/client"
	"github.com/tempoxyz/tempo-go/pkg/signer"
)

func main() {
	cfg, err := server.LoadConfigFromEnv()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	cfg.Print()

	sgn, err := signer.NewSigner(cfg.FeePayerPrivateKey)
	if err != nil {
		log.Fatalf("Failed to create signer: %v", err)
	}

	tempoClient := client.New(
		cfg.TempoRPCURL,
		client.WithAuth(cfg.TempoUsername, cfg.TempoPassword),
	)

	feePayerServer := server.NewFeePayerServer(
		cfg.Port,
		sgn,
		tempoClient,
		cfg.AlphaUSDAddress,
	)

	log.Fatal(feePayerServer.Start())
}
