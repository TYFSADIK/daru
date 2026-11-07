# Daru build and dev tasks.
BINARY := daru
PKG := ./cmd/daru
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build test vet fmt run install clean docker release tools help

all: build

build: ## Build the daru binary for this platform
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) $(PKG)

test: ## Run the unit test suite
	go test ./...

vet: ## Run go vet
	go vet ./...

fmt: ## Format the code
	gofmt -w .

run: build ## Build and run the server
	./$(BINARY) serve

install: ## Install Daru and ClickHouse (one command)
	sh ./install.sh

tools: ## Install optional security scanners (opt-in, prompts first)
	sh ./scripts/install-recon-tools.sh

docker: ## Build and start everything with Docker Compose
	cd deploy && docker compose up -d --build

clean:
	rm -f $(BINARY) $(BINARY).exe
	rm -rf dist

# Cross-compile release binaries for every supported platform.
PLATFORMS := linux/amd64 linux/arm64 linux/arm darwin/amd64 darwin/arm64 windows/amd64 android/arm64
release: ## Cross-compile binaries into dist/
	@mkdir -p dist
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		ext=""; [ "$$os" = windows ] && ext=".exe"; \
		out="dist/$(BINARY)-$$os-$$arch$$ext"; \
		echo "building $$out"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o "$$out" $(PKG) || exit 1; \
	done
	@echo "done; binaries in dist/"

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'
