# Build confide with your OAuth client credentials baked into the binary,
# so the only thing you distribute to teammates is the binary itself.
#
# Provide credentials via the environment or a local .env file (git-ignored):
#
#   CLIENT_ID=xxxx.apps.googleusercontent.com
#   CLIENT_SECRET=xxxx
#
# Then: `make` (or `make build`). Teammates just run `./confide login`.

-include .env
export

PKG := github.com/maxinielsen/confide/internal/drive
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X $(PKG).buildClientID=$(CLIENT_ID) -X $(PKG).buildClientSecret=$(CLIENT_SECRET) \
	-X github.com/maxinielsen/confide/cmd.version=$(VERSION)

.PHONY: build test vet clean

build:
ifndef CLIENT_ID
	$(error CLIENT_ID is not set — put it in .env or the environment)
endif
	go build -ldflags "$(LDFLAGS)" -o confide .
	@echo "Built ./confide with embedded OAuth client $(CLIENT_ID)"

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -f confide
