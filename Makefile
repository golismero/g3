.PHONY: all bin clean misc docker plugins

GO := $(shell command -v go 2> /dev/null)

# Build the binaries locally.
ifdef GO
bin: clean
	mkdir -p bin/ config/
	cd src && CGO_ENABLED=0 $(MAKE)
endif

# Clean the binaries locally.
ifdef GO
clean:
	rm -f bin/g3*
endif

# Install the binaries locally.
ifdef GO
install:
	sudo ln -s -f $$(pwd)/bin/g3 /usr/bin/g3
	sudo ln -s -f $$(pwd)/bin/g3api /usr/bin/g3api
	sudo ln -s -f $$(pwd)/bin/g3cli /usr/bin/g3cli
	sudo ln -s -f $$(pwd)/bin/g3config /usr/bin/g3config
	sudo ln -s -f $$(pwd)/bin/g3scanner /usr/bin/g3scanner
	sudo ln -s -f $$(pwd)/bin/g3worker /usr/bin/g3worker
endif

# Produce all of the Docker images.
ifdef GO
all: bin misc docker plugins
else
all: misc docker plugins
endif

# Install the build requirements.
misc:
	pip3 install -r misc/requirements.txt

# Build the g3 Docker image.
docker:
	rm -f ./misc/deps.txt
ifdef GO
	cd src; for d in */; do cd "$$d"; go mod tidy; cd ..; done
endif
	./misc/collect-go-deps.py ./misc/deps.txt
	docker build -t golismero3/g3bin .

# Build all of the Docker images for the plugins.
ifdef GO
plugins:
	cd plugins && $(MAKE)
	./bin/g3config
else
plugins: docker
	cd plugins && $(MAKE)
	docker run --entrypoint /bin/g3config --volume $$(pwd):/app --volume /var/run/docker.sock:/var/run/docker.sock --env G3HOME=/app golismero3/g3bin
endif
