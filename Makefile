# Everything runs in containers: no local Go needed. Override: make test GO=go
SHELL := /bin/bash
.DEFAULT_GOAL := help

GO_IMAGE := golang:1.26

DOCKER_RUN := docker run --rm -u $(shell id -u):$(shell id -g) -v $(CURDIR):/src -w /src \
              -e GOCACHE=/src/.cache/build -e GOMODCACHE=/src/.cache/mod -e HOME=/tmp
GO ?= $(DOCKER_RUN) $(GO_IMAGE) go

.PHONY: help deps fmt fmt-check vet test integration vuln check
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

integration: ## events tests against real NATS JetStream and Postgres (throw-away containers)
	@docker rm -f kit-it-nats kit-it-pg >/dev/null 2>&1 || true
	docker run -d --name kit-it-nats -p 127.0.0.1:14222:4222 nats:2.15-alpine -js >/dev/null
	docker run -d --name kit-it-pg -p 127.0.0.1:15432:5432 -e POSTGRES_PASSWORD=kit -e POSTGRES_DB=kit postgres:18 >/dev/null
	@for i in $$(seq 1 60); do docker exec kit-it-pg pg_isready -h 127.0.0.1 -U postgres -q && break; sleep 1; done
	@$(DOCKER_RUN) --network host -e CGO_ENABLED=1 -e KIT_TEST_NATS_URL=nats://127.0.0.1:14222 \
	  -e KIT_TEST_DATABASE_URL='postgres://postgres:kit@127.0.0.1:15432/kit?sslmode=disable' \
	  $(GO_IMAGE) go test -race -count=1 -v ./events/; s=$$?; docker rm -f kit-it-nats kit-it-pg >/dev/null; exit $$s

vuln: ## known vulnerabilities in reachable code
	$(DOCKER_RUN) $(GO_IMAGE) sh -c 'go run golang.org/x/vuln/cmd/govulncheck@latest ./...'

check: fmt-check vet test integration ## everything CI runs (except govulncheck: make vuln)
