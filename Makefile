# Everything runs in containers: no local Go needed. Override: make test GO=go
SHELL := /bin/bash
.DEFAULT_GOAL := help

GO_IMAGE := golang:1.26

DOCKER_RUN := docker run --rm -u $(shell id -u):$(shell id -g) -v $(CURDIR):/src -w /src \
              -e GOCACHE=/src/.cache/build -e GOMODCACHE=/src/.cache/mod -e HOME=/tmp
GO ?= $(DOCKER_RUN) $(GO_IMAGE) go

.PHONY: help deps fmt fmt-check vet test vuln check
help: ## list targets
	@grep -hE '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'

deps: ## resolve modules and write go.sum (go mod tidy)
	$(GO) mod tidy

fmt: ## format the code
	$(GO) fmt ./...

fmt-check: ## fail if any file isn't formatted
	@out=$$($(DOCKER_RUN) $(GO_IMAGE) sh -c 'gofmt -l $$(go list -f "{{.Dir}}" ./...)'); \
	test -z "$$out" || { echo "$$out"; echo "run: make fmt"; exit 1; }

vet: ## go vet
	$(GO) vet ./...

test: ## tests with the race detector
	$(DOCKER_RUN) -e CGO_ENABLED=1 $(GO_IMAGE) go test -race -count=1 ./...

vuln: ## known vulnerabilities in reachable code
	$(DOCKER_RUN) $(GO_IMAGE) sh -c 'go run golang.org/x/vuln/cmd/govulncheck@latest ./...'

check: fmt-check vet test ## everything CI runs (except govulncheck: make vuln)
