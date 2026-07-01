.PHONY: all update lint g3lib g3

GO_FLAGS   ?=
GO_LDFLAGS ?=

# Internal sibling modules are resolved via local `replace` directives, so their
# require version is only a cosmetic label. `go get -u` insists on stamping it
# with the latest VCS pseudo-version anyway; we pin it back to the zero version
# to keep local builds reproducible and out of the go.mod diff. (`go work sync`
# in the root Makefile then propagates this — but only because every module is
# zero by the time it runs.)
INTERNAL_PREFIX := github.com/golismero/g3/src/
ZERO_VERSION    := v0.0.0-00010101000000-000000000000

all: ../bin/g3 ../bin/g3api ../bin/g3cli ../bin/g3config ../bin/g3scanner ../bin/g3tui ../bin/g3worker

# Client-side SDK.

g3:
	cd g3 && go build -ldflags="$(GO_LDFLAGS)"

# Server-side SDK.

g3lib: g3
	cd g3lib && go build -ldflags="$(GO_LDFLAGS)"

# Client-side tools.

../bin/g3cli: g3lib
	cd g3cli && go build $(GO_FLAGS) -ldflags="$(GO_LDFLAGS)" -o ../../bin/g3cli

../bin/g3tui: g3lib
	cd g3tui && go build $(GO_FLAGS) -ldflags="$(GO_LDFLAGS)" -o ../../bin/g3tui

# Server-side tools.

../bin/g3: g3lib 
	cd g3bin && go build $(GO_FLAGS) -ldflags="$(GO_LDFLAGS)" -o ../../bin/g3

../bin/g3api: g3lib
	cd g3api && go build $(GO_FLAGS) -ldflags="$(GO_LDFLAGS)" -o ../../bin/g3api

../bin/g3config: g3lib
	cd g3config && go build $(GO_FLAGS) -ldflags="$(GO_LDFLAGS)" -o ../../bin/g3config

../bin/g3scanner: g3lib
	cd g3scanner && go build $(GO_FLAGS) -ldflags="$(GO_LDFLAGS)" -o ../../bin/g3scanner

../bin/g3worker: g3lib
	cd g3worker && go build $(GO_FLAGS) -ldflags="$(GO_LDFLAGS)" -o ../../bin/g3worker

# Code maintenance tasks.

update:
	set -e; for d in */; do ( \
		cd "$$d" && echo "Upgrading: $$d" && \
		go mod tidy && go get -u ./... && go mod tidy && \
		for m in $$(grep -E '^[[:space:]]+$(INTERNAL_PREFIX)[A-Za-z0-9_-]+ v[0-9]' go.mod | awk '{print $$1}'); do \
			go mod edit -require="$$m@$(ZERO_VERSION)"; \
		done \
	); done

lint:
	set -e; for d in */; do (cd "$$d" && echo "Linting: $$d" && golangci-lint run); done
