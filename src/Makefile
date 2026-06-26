.PHONY: all update lint g3lib g3log g3model

GO_FLAGS   ?=
GO_LDFLAGS ?=

all: ../bin/g3 ../bin/g3api ../bin/g3cli ../bin/g3config ../bin/g3scanner ../bin/g3tui ../bin/g3worker

g3log:
	cd g3log && go build -ldflags="$(GO_LDFLAGS)"

g3model:
	cd g3model && go build -ldflags="$(GO_LDFLAGS)"

g3lib: g3log g3model
	cd g3lib && go build -ldflags="$(GO_LDFLAGS)"

../bin/g3: g3lib 
	cd g3 && go build $(GO_FLAGS) -ldflags="$(GO_LDFLAGS)" -o ../../bin/g3

../bin/g3api: g3lib
	cd g3api && go build $(GO_FLAGS) -ldflags="$(GO_LDFLAGS)" -o ../../bin/g3api

../bin/g3cli: g3lib
	cd g3cli && go build $(GO_FLAGS) -ldflags="$(GO_LDFLAGS)" -o ../../bin/g3cli

../bin/g3config: g3lib
	cd g3config && go build $(GO_FLAGS) -ldflags="$(GO_LDFLAGS)" -o ../../bin/g3config

../bin/g3scanner: g3lib
	cd g3scanner && go build $(GO_FLAGS) -ldflags="$(GO_LDFLAGS)" -o ../../bin/g3scanner

../bin/g3tui: g3lib
	cd g3tui && go build $(GO_FLAGS) -ldflags="$(GO_LDFLAGS)" -o ../../bin/g3tui

../bin/g3worker: g3lib
	cd g3worker && go build $(GO_FLAGS) -ldflags="$(GO_LDFLAGS)" -o ../../bin/g3worker

update:
	set -e; for d in */; do (cd "$$d" && echo "Upgrading: $$d" && go mod tidy && go get -u ./... && go mod tidy); done

lint:
	set -e; for d in */; do (cd "$$d" && echo "Linting: $$d" && golangci-lint run); done
