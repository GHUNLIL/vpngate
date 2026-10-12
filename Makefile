VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
REPO    ?= GHUNLIL/vpngate
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.repo=$(REPO)
export CGO_ENABLED=0

.PHONY: build test release clean
build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o vpngate .

test:
	go vet ./... && CGO_ENABLED=1 go test -race ./...

# Static Linux binaries for every supported VPS architecture.
release:
	@mkdir -p dist
	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/vpngate-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/vpngate-linux-arm64 .
	GOOS=linux GOARCH=arm GOARM=7 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/vpngate-linux-armv7 .
	GOOS=linux GOARCH=386 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/vpngate-linux-386 .
	cp install.sh dist/
	cd dist && sha256sum vpngate-linux-* > SHA256SUMS 2>/dev/null || shasum -a 256 vpngate-linux-* > SHA256SUMS

clean:
	rm -rf dist vpngate
