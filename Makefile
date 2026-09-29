GO        ?= go
BIN       ?= bin/barerelic
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS   := -s -w -X github.com/shanurwan/barerelic/internal/buildinfo.Version=$(VERSION)
FUZZTIME  ?= 30s
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

.PHONY: all build test race cover vet fmt-check lint vuln fuzz cross demo check clean

all: check build

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/barerelic

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

cover:
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out | tail -1

vet:
	$(GO) vet ./...

fmt-check:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

lint:
	$(GO) run honnef.co/go/tools/cmd/staticcheck@v0.8.1 ./...

vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...

# Short fuzzing pass over every parser that handles untrusted evidence.
fuzz:
	$(GO) test ./internal/fs/ntfs     -run '^$$' -fuzz '^FuzzParseRecord$$' -fuzztime $(FUZZTIME)
	$(GO) test ./internal/fs/ntfs     -run '^$$' -fuzz '^FuzzDecodeRuns$$'  -fuzztime $(FUZZTIME)
	$(GO) test ./internal/fs/fat      -run '^$$' -fuzz '^FuzzParseBootSector$$' -fuzztime $(FUZZTIME)
	$(GO) test ./internal/fs/fat      -run '^$$' -fuzz '^FuzzWalk$$'        -fuzztime $(FUZZTIME)
	$(GO) test ./internal/carve       -run '^$$' -fuzz '^FuzzValidators$$'  -fuzztime $(FUZZTIME)
	$(GO) test ./internal/volume      -run '^$$' -fuzz '^FuzzRead$$'        -fuzztime $(FUZZTIME)
	$(GO) test ./internal/rescuemap   -run '^$$' -fuzz '^FuzzParse$$'       -fuzztime $(FUZZTIME)

cross:
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=; [ $$os = windows ] && ext=.exe; \
		echo "build $$p"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags '$(LDFLAGS)' \
			-o dist/barerelic-$$os-$$arch$$ext ./cmd/barerelic || exit 1; \
	done
	cd dist && sha256sum barerelic-* > SHA256SUMS

# Build the synthetic evidence disk used by the end-to-end test and walk the
# full workflow against it. Nothing touches a real device.
demo: build
	mkdir -p demo
	BARERELIC_DEMO_DISK=$(CURDIR)/demo/disk.raw $(GO) test ./internal/cli -run '^TestWriteDemoDisk$$' -count=1
	rm -rf demo/evidence.img demo/evidence.img.map demo/evidence.img.barerelic.json demo/case demo/carved
	$(BIN) image   --out demo/evidence.img demo/disk.raw
	$(BIN) verify  demo/evidence.img
	$(BIN) probe   --scan demo/evidence.img
	$(BIN) recover --out demo/case demo/evidence.img
	$(BIN) carve   --types png --out demo/carved demo/evidence.img
	$(BIN) verify  demo/case

check: fmt-check vet test

clean:
	rm -rf bin dist demo coverage.out
