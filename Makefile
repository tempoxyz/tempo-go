.PHONY: build_examples clean test check lint tidy-check vulncheck fix help integration docs fuzz fuzz-all

# Go modules in this repository
MODULES := . tests examples/feepayer examples/parallel-nonces

# Pinned tool versions (go run fetches and caches them)
STATICCHECK := honnef.co/go/tools/cmd/staticcheck@v0.8.2
GOVULNCHECK := golang.org/x/vuln/cmd/govulncheck@v1.9.0

# Default target
all: check

# Builds all examples
build_examples:
	cd examples/feepayer && go build -o ../../bin/feepayer ./cmd
	go build -o bin/simple-send ./examples/simple-send
	cd examples/parallel-nonces && go build -o ../../bin/parallel-nonces .

# Cleans all targets
clean:
	go clean
	rm -rf bin/
	rm -f cover.out cover.html coverage.out

# Run unit tests only (excludes integration tests)
test:
	go test -race ./pkg/...

# Run unit tests with coverage
test-coverage:
	go test -race -coverprofile=coverage.out ./pkg/...
	go tool cover -html=coverage.out -o cover.html

# Run checks as well as unit tests
check:
	go mod verify
	test -z "$$(gofmt -s -l .)" || (echo "Code needs formatting. Run 'make fix'" && gofmt -s -l . && exit 1)
	go vet ./...
	cd tests && go vet ./...
	cd examples/feepayer && go vet ./...
	cd examples/parallel-nonces && go vet ./...
	go test -race ./pkg/...

# Fails when any module's go.mod or go.sum is not tidy
tidy-check:
	@for m in $(MODULES); do echo "go mod tidy -diff: $$m"; (cd $$m && go mod tidy -diff) || exit 1; done

# Runs staticcheck on every module
lint:
	@for m in $(MODULES); do echo "staticcheck: $$m"; (cd $$m && go run $(STATICCHECK) ./...) || exit 1; done

# Reports known vulnerabilities reachable from the library and examples
vulncheck:
	go run $(GOVULNCHECK) ./...
	cd examples/feepayer && go run $(GOVULNCHECK) ./...
	cd examples/parallel-nonces && go run $(GOVULNCHECK) ./...

# Formats code and tidies dependencies
fix:
	gofmt -s -w .
	go mod tidy
	cd tests && go mod tidy
	cd examples/feepayer && go mod tidy
	cd examples/parallel-nonces && go mod tidy

# Run integration tests only (uses docker-compose tempo node by default)
integration:
	@cd tests && TEMPO_RPC_URL=$${TEMPO_RPC_URL:-http://localhost:8545} go test -count=1 -run TestIntegration -timeout=10m .

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
	@for pkg in ./pkg/transaction ./pkg/signer ./pkg/keychain; do \
		echo "=== Fuzzing $$pkg ==="; \
		for test in $$(go test -list 'Fuzz.*' $$pkg 2>/dev/null | grep '^Fuzz'); do \
			echo "Running $$test..."; \
			go test -fuzz=$$test -fuzztime=$(FUZZTIME) $$pkg || exit 1; \
		done; \
	done
	@echo "=== All fuzz tests complete ==="
