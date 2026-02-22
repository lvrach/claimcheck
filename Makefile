GO ?= go

GOLANGCI=github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.9.0
gofumpt=mvdan.cc/gofumpt@v0.9.2
govulncheck=golang.org/x/vuln/cmd/govulncheck@v1.1.4
goimports=golang.org/x/tools/cmd/goimports@v0.42.0
gosec=github.com/securego/gosec/v2/cmd/gosec@v2.23.0
gitleaks=github.com/zricethezav/gitleaks/v8@v8.21.2

actionlint=github.com/rhysd/actionlint/cmd/actionlint@latest

.PHONY: fmt
fmt:
	$(GO) mod tidy
	$(GO) fix ./...
	$(GO) run $(gofumpt) -l -w -extra .
	$(GO) run $(goimports) -format-only -w -local=claimcheck .

.PHONY: lint
lint: fmt
	$(GO) run $(GOLANGCI) run -v

.PHONY: test
test:
	$(GO) test -race -v -failfast -shuffle=on \
	  -coverprofile=coverage.txt -covermode=atomic \
	  -vet=all -timeout=15m -count=1 ./...

.PHONY: sec
sec:
	$(GO) run $(gitleaks) detect --source .
	$(GO) run $(govulncheck) ./...
	$(GO) run $(gosec) -fmt=text ./...
