.PHONY: all g3lib g3log

all: ../bin/g3 ../bin/g3api ../bin/g3cli ../bin/g3config ../bin/g3scanner ../bin/g3worker

g3lib:
	cd g3lib && go mod tidy && go build

g3log:
	cd g3log && go mod tidy && go build

../bin/g3: g3lib g3log
	cd g3 && go mod tidy && go build -o ../../bin/g3

../bin/g3api: g3lib g3log
	cd g3api && go mod tidy && go build -o ../../bin/g3api

../bin/g3cli: g3lib g3log
	cd g3cli && go mod tidy && go build -o ../../bin/g3cli

../bin/g3config: g3lib g3log
	cd g3config && go mod tidy && go build -o ../../bin/g3config

../bin/g3scanner: g3lib g3log
	cd g3scanner && go mod tidy && go build -o ../../bin/g3scanner

../bin/g3worker: g3lib g3log
	cd g3worker && go mod tidy && go build -o ../../bin/g3worker
