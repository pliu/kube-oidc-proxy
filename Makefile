# Copyright Jetstack Ltd. See LICENSE for details.
BINDIR    ?= $(CURDIR)/bin
HACK_DIR  ?= hack
ARTIFACTS ?= artifacts
ARCH      ?= amd64

SHELL = /bin/bash -o pipefail

export GO111MODULE=on

help:  ## display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} /^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

.PHONY: help build docker_build test integration verify all clean generate

verify_boilerplate:
	$(HACK_DIR)/verify-boilerplate.sh

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
		$(CURDIR)/pkg/mocks/authenticator.go \
		$(CURDIR)/demo/bin \
		$(CURDIR)/test/e2e/framework/issuer/bin \
		$(CURDIR)/test/e2e/framework/fake-apiserver/bin

verify: verify_boilerplate go_fmt go_vet ## verify code and mod

generate: ## generates mocks and assets files
	go generate $$(go list ./pkg/... ./cmd/...)

test: generate verify ## run all go tests
	mkdir -p $(ARTIFACTS)
	go test -v -bench $$(go list ./pkg/... ./cmd/... | grep -v pkg/e2e) | tee $(ARTIFACTS)/go-test.stdout
	cat $(ARTIFACTS)/go-test.stdout | go run github.com/jstemmer/go-junit-report > $(ARTIFACTS)/junit-go-test.xml

integration: ## run in-process integration tests
	go test -v --count=1 ./test/integration/...

e2e: ## run end to end tests; needs Docker and kubectl
	mkdir -p $(ARTIFACTS)
	KUBE_OIDC_PROXY_ROOT_PATH="$$(pwd)" go test -timeout 30m -v --count=1 ./test/e2e/suite/.

build: generate ## build kube-oidc-proxy
	mkdir -p ./bin/amd64
	mkdir -p ./bin/arm64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags '-w $(shell hack/version-ldflags.sh)' -o ./bin/amd64/kube-oidc-proxy ./cmd/.
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags '-w $(shell hack/version-ldflags.sh)' -o ./bin/arm64/kube-oidc-proxy ./cmd/.

docker_build: generate test build ## build docker image
	GOARCH=$(ARCH) GOOS=linux CGO_ENABLED=0 go build -ldflags '-w $(shell hack/version-ldflags.sh)' -o ./bin/kube-oidc-proxy  ./cmd/.
	docker build -t kube-oidc-proxy .

all: test build ## runs tests, build

image: all docker_build ## runs tests, build and docker build

dev_cluster_create: ## create dev cluster for development testing
	KUBE_OIDC_PROXY_ROOT_PATH="$$(pwd)" go run -v ./test/environment/dev create

dev_cluster_deploy: ## deploy into dev cluster
	KUBE_OIDC_PROXY_ROOT_PATH="$$(pwd)" go run -v ./test/environment/dev deploy

dev_cluster_destroy: ## destroy dev cluster
	KUBE_OIDC_PROXY_ROOT_PATH="$$(pwd)" go run -v ./test/environment/dev destroy
