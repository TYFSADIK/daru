# Daru build and dev tasks.
BINARY := daru
PKG := ./cmd/daru
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build test vet fmt run install clean docker release tools help stamp-version backup restore

all: build

stamp-version: ## Stamp the release version into the web UI footer (index.html data-version)
	@sed -i 's/data-version="[^"]*"/data-version="$(VERSION)"/; s/>Daru [^<]*</>Daru $(VERSION)</' internal/web/static/index.html
	@echo "stamped UI version $(VERSION)"

backup: ## Back up the Daru ClickHouse database (see scripts/backup.sh)
	./scripts/backup.sh

restore: ## Restore the Daru ClickHouse database (BACKUP_FILE=... make restore)
	./scripts/restore.sh $(BACKUP_FILE)

build: ## Build the daru binary for this platform
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) $(PKG)

test: ## Run the unit test suite
	go test ./...

vet: ## Run go vet
	go vet ./...

fmt: ## Format the code
	gofmt -w .

run: build ## Build and run the server (ClickHouse must already be running, see README)
	./$(BINARY) serve

install: ## Install Daru and ClickHouse (one command)
	bash ./install.sh

tools: ## Install optional security scanners (opt-in, prompts first)
	sh ./scripts/install-recon-tools.sh

docker: ## Build and start everything with Docker Compose
	cd deploy && docker compose up -d --build --build-arg VERSION=$(VERSION)

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
