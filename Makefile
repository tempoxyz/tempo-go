.PHONY: build_examples clean test check fix help integration docs fuzz fuzz-all

# Default target
all: check

# Builds all examples
build_examples:
	cd examples/feepayer && go build -o ../../bin/feepayer ./cmd
	go build -o bin/simple-send ./examples/simple-send

# Cleans all targets
clean:
	go clean
	rm -rf bin/
	rm -f cover.out cover.html coverage.out

# Run unit tests only (excludes integration tests)
test:
	go test -race ./pkg/transaction ./pkg/signer ./pkg/client

# Run unit tests with coverage
test-coverage:
	go test -race -coverprofile=coverage.out ./pkg/transaction ./pkg/signer ./pkg/client
	go tool cover -html=coverage.out -o cover.html

# Run checks as well as unit tests
check:
	test -z "$$(gofmt -l .)" || (echo "Code needs formatting. Run 'make fix'" && gofmt -l . && exit 1)
	go vet ./...
	go test -race ./pkg/transaction ./pkg/signer ./pkg/client

# Formats code and tidies dependencies
fix:
	gofmt -s -w .
	go mod tidy
	cd examples/feepayer && go mod tidy

# Run integration tests only (uses docker-compose tempo node by default)
integration:
	@TEMPO_RPC_URL=$${TEMPO_RPC_URL:-http://localhost:8545} go test -run TestIntegration -timeout=5m ./tests

# Start godoc server for viewing documentation
docs:
	which godoc > /dev/null || (echo "Installing godoc..." && go install golang.org/x/tools/cmd/godoc@latest)
	echo "Documentation available at http://localhost:6060/pkg/github.com/tempoxyz/tempo-go/"
	echo "Press Ctrl+C to stop the server"
	@godoc -http=:6060

# Fuzz test duration (default 10s, override with FUZZTIME=1m)
FUZZTIME ?= 10s

# Run a single fuzz test: make fuzz FUZZ=FuzzTestName PKG=./pkg/transaction/
fuzz:
ifndef FUZZ
	$(error Usage: make fuzz FUZZ=FuzzTestName PKG=./pkg/package/)
endif
ifndef PKG
	$(error Usage: make fuzz FUZZ=FuzzTestName PKG=./pkg/package/)
endif
	go test -fuzz=$(FUZZ) -fuzztime=$(FUZZTIME) $(PKG)

# Run all fuzz tests sequentially
fuzz-all:
	@for pkg in ./pkg/transaction ./pkg/signer; do \
		echo "=== Fuzzing $$pkg ==="; \
		for test in $$(go test -list 'Fuzz.*' $$pkg 2>/dev/null | grep '^Fuzz'); do \
			echo "Running $$test..."; \
			go test -fuzz=$$test -fuzztime=$(FUZZTIME) $$pkg || exit 1; \
		done; \
	done
	@echo "=== All fuzz tests complete ==="
