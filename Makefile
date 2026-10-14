# Copyright Jetstack Ltd. See LICENSE for details.
BINDIR    ?= $(CURDIR)/bin
ARTIFACTS ?= artifacts
ARCH      ?= amd64

SHELL = /bin/bash -o pipefail

export GO111MODULE=on

help:  ## display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} /^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

.PHONY: help build docker_build test e2e verify all clean

go_fmt:
	@set -e; \
	GO_FMT=$$(git ls-files *.go | xargs gofmt -d); \
	if [ -n "$${GO_FMT}" ] ; then \
		echo "Please run go fmt"; \
		echo "$$GO_FMT"; \
		exit 1; \
	fi

go_vet:
	go vet ./cmd

go_lint: ## lint golang code for problems, with the golangci-lint on PATH
	golangci-lint run --timeout 3m

clean: ## clean up created files
	rm -rf \
		$(BINDIR) \
		$(CURDIR)/test/e2e/framework/issuer/bin \
		$(CURDIR)/test/e2e/framework/fake-apiserver/bin

verify: go_fmt go_vet ## verify code and mod

test: verify ## run unit and in-process integration tests; needs nothing external
	go test -v --count=1 ./pkg/... ./cmd/... ./test/integration/...

e2e: ## run end to end tests in a kind cluster; needs Docker and kubectl
	mkdir -p $(ARTIFACTS)
	KUBE_OIDC_PROXY_ROOT_PATH="$$(pwd)" ARTIFACTS="$(abspath $(ARTIFACTS))" go test -timeout 60m -v --count=1 ./test/e2e/suite/.

build: ## build kube-oidc-proxy
	mkdir -p ./bin/amd64
	mkdir -p ./bin/arm64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ./bin/amd64/kube-oidc-proxy ./cmd/.
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o ./bin/arm64/kube-oidc-proxy ./cmd/.

docker_build: test build ## build docker image
	GOARCH=$(ARCH) GOOS=linux CGO_ENABLED=0 go build -o ./bin/kube-oidc-proxy ./cmd/.
	docker build -t kube-oidc-proxy .

all: test build ## runs tests, build

image: all docker_build ## runs tests, build and docker build

dev_cluster_create: ## create dev cluster for development testing
	KUBE_OIDC_PROXY_ROOT_PATH="$$(pwd)" go run -v ./test/environment/dev create

dev_cluster_deploy: ## deploy into dev cluster
	KUBE_OIDC_PROXY_ROOT_PATH="$$(pwd)" go run -v ./test/environment/dev deploy

dev_cluster_destroy: ## destroy dev cluster
	KUBE_OIDC_PROXY_ROOT_PATH="$$(pwd)" go run -v ./test/environment/dev destroy
