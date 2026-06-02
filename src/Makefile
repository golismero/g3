.PHONY: all update lint g3lib g3log

# Optional build flags, empty by default so a bare `make` produces debuggable
# binaries for local development. Release builds (the Dockerfile, CI) override
# them on the command line to strip symbols, trim paths, and stamp a version:
#   make all GO_FLAGS=-trimpath GO_LDFLAGS="-s -w -X main.Version=v1.2.3"
# -X targets `main.Version`, which only g3/g3cli/g3tui define; the linker
# silently ignores it for the daemons, so a single value is safe for all.
GO_FLAGS   ?=
GO_LDFLAGS ?=

all: ../bin/g3 ../bin/g3api ../bin/g3cli ../bin/g3config ../bin/g3scanner ../bin/g3tui ../bin/g3worker

g3lib:
	cd g3lib && go mod tidy && go build

g3log:
	cd g3log && go mod tidy && go build

../bin/g3: g3lib g3log
	cd g3 && go mod tidy && go build $(GO_FLAGS) -ldflags="$(GO_LDFLAGS)" -o ../../bin/g3

../bin/g3api: g3lib g3log
	cd g3api && go mod tidy && go build $(GO_FLAGS) -ldflags="$(GO_LDFLAGS)" -o ../../bin/g3api

../bin/g3cli: g3lib g3log
	cd g3cli && go mod tidy && go build $(GO_FLAGS) -ldflags="$(GO_LDFLAGS)" -o ../../bin/g3cli

../bin/g3config: g3lib g3log
	cd g3config && go mod tidy && go build $(GO_FLAGS) -ldflags="$(GO_LDFLAGS)" -o ../../bin/g3config

../bin/g3scanner: g3lib g3log
	cd g3scanner && go mod tidy && go build $(GO_FLAGS) -ldflags="$(GO_LDFLAGS)" -o ../../bin/g3scanner

../bin/g3tui: g3lib g3log
	cd g3tui && go mod tidy && go build $(GO_FLAGS) -ldflags="$(GO_LDFLAGS)" -o ../../bin/g3tui

../bin/g3worker: g3lib g3log
	cd g3worker && go mod tidy && go build $(GO_FLAGS) -ldflags="$(GO_LDFLAGS)" -o ../../bin/g3worker

update:
	set -e; for d in */; do (cd "$$d" && echo "Upgrading: $$d" && go get -u ./... && go mod tidy); done

lint:
	set -e; for d in */; do (cd "$$d" && echo "Linting: $$d" && golangci-lint run); done
