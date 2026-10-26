BINARY := bin/ofc
PKG    := ./...
IMAGE  := dillmann/open-folio-connect
VERSION := $(shell sed -n 's/^var version = "\(.*\)"$$/\1/p' cmd/ofc/constants.go)
PLATFORMS ?= linux/amd64,linux/arm64
LDFLAGS := -s -w -X main.version=$(VERSION)
LINUX_BINARIES := bin/ofc-linux-amd64 bin/ofc-linux-arm64

.PHONY: build run lint format tidy test docker-build clean FORCE

FORCE:

.prerequisites:
ifeq ($(CI),true)
	go mod download
	cd tools && go mod download
else
	go mod tidy
	cd tools && go mod tidy
endif

build:
	go build -o $(BINARY) ./cmd/ofc

bin/ofc-linux-%: FORCE
	@mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=$* go build -trimpath -ldflags "$(LDFLAGS)" -o $@ ./cmd/ofc

run:
	go run ./cmd/ofc

lint: .prerequisites
	go tool -modfile=tools/go.mod golangci-lint run ./internal/...
	go vet $(PKG)

format: .prerequisites
	go tool -modfile=tools/go.mod fieldalignment -fix ./internal/...
	go tool -modfile=tools/go.mod golangci-lint run --fix ./internal/...

tidy:
	go mod tidy

test:
	@./tools/e2e.sh

docker-build: $(LINUX_BINARIES)
	@if [ -z "$(VERSION)" ]; then \
		echo "could not read the version from cmd/ofc/constants.go"; exit 1; \
	fi
	@if ! docker buildx inspect ofc-builder >/dev/null 2>&1; then \
		echo "==> creating the ofc-builder buildx builder"; \
		docker buildx create --name ofc-builder --driver docker-container --bootstrap >/dev/null || exit 1; \
	fi
	@echo "==> building $(IMAGE):$(VERSION) and $(IMAGE):latest for $(PLATFORMS)"
	docker buildx build \
		--builder ofc-builder \
		--platform $(PLATFORMS) \
		--label org.opencontainers.image.title="open-folio-connect" \
		--label org.opencontainers.image.version="$(VERSION)" \
		--label org.opencontainers.image.source="https://github.com/lucasdillmann/open-folio-connect" \
		--tag $(IMAGE):$(VERSION) \
		--tag $(IMAGE):latest \
		--push \
		.
	@echo "==> published $(IMAGE):$(VERSION) and $(IMAGE):latest"

clean:
	rm -rf bin
