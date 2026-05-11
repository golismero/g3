.PHONY: all bin clean misc docker plugins pull update install help

# Default target — show help when invoked as bare `make`.
.DEFAULT_GOAL := help

GO     := $(shell command -v go 2> /dev/null)
DOCKER := $(shell command -v docker 2> /dev/null)
PYTHON := $(shell command -v python3 2> /dev/null)

# ANSI escape codes for the help target.
C_RESET  := \033[0m
C_BOLD   := \033[1m
C_DIM    := \033[2m
C_RED    := \033[31m
C_GREEN  := \033[32m
C_YELLOW := \033[33m
C_CYAN   := \033[36m

# Print a colorized summary of the available targets,
# tailored to whichever toolchain (Go, Docker) is present.
help:
	@printf "$(C_BOLD)Golismero 3$(C_RESET)\n\n"
	@printf "$(C_BOLD)Toolchain:$(C_RESET)\n"
ifdef GO
	@printf "  $(C_GREEN)Go$(C_RESET)       $(C_DIM)$(GO)$(C_RESET)\n"
else
	@printf "  $(C_RED)Go$(C_RESET)       $(C_DIM)not found — Go-only targets are disabled$(C_RESET)\n"
endif
ifdef DOCKER
	@printf "  $(C_GREEN)Docker$(C_RESET)   $(C_DIM)$(DOCKER)$(C_RESET)\n"
else
	@printf "  $(C_RED)Docker$(C_RESET)   $(C_DIM)not found — image targets will fail$(C_RESET)\n"
endif
ifdef PYTHON
	@printf "  $(C_GREEN)Python$(C_RESET)   $(C_DIM)$(PYTHON)$(C_RESET)\n"
else
	@printf "  $(C_RED)Python$(C_RESET)   $(C_DIM)not found — some targets may fail$(C_RESET)\n"
endif
	@printf "\n$(C_BOLD)Targets:$(C_RESET)\n"
	@printf "  $(C_CYAN)help$(C_RESET)     Show this message\n"
ifdef GO
ifdef DOCKER
	@printf "  $(C_CYAN)all$(C_RESET)      Build Go binaries and all Docker images\n"
else
	@printf "  $(C_CYAN)all$(C_RESET)      Build Go binaries $(C_DIM)(no Docker: images skipped)$(C_RESET)\n"
endif
	@printf "  $(C_CYAN)bin$(C_RESET)      Compile the Go binaries into ./bin/\n"
	@printf "  $(C_CYAN)clean$(C_RESET)    Remove the compiled binaries from ./bin/\n"
	@printf "  $(C_CYAN)install$(C_RESET)  Symlink ./bin/g3* into /usr/bin/ (requires sudo)\n"
	@printf "  $(C_CYAN)update$(C_RESET)   Update all Go module dependencies\n"
else
ifdef DOCKER
	@printf "  $(C_CYAN)all$(C_RESET)      Build all Docker images $(C_DIM)(no Go: bin/clean/install skipped)$(C_RESET)\n"
else
	@printf "  $(C_DIM)all                (disabled — Go and Docker not detected)$(C_RESET)\n"
endif
	@printf "  $(C_DIM)bin                (disabled — Go not detected)$(C_RESET)\n"
	@printf "  $(C_DIM)clean              (disabled — Go not detected)$(C_RESET)\n"
	@printf "  $(C_DIM)install            (disabled — Go not detected)$(C_RESET)\n"
	@printf "  $(C_DIM)update             (disabled — Go not detected)$(C_RESET)\n"
endif
ifdef PYTHON
	@printf "  $(C_CYAN)misc$(C_RESET)     Install Python build requirements (misc/requirements.txt)\n"
else
	@printf "  $(C_DIM)misc               (disabled — Python not detected)$(C_RESET)\n"
endif
ifdef DOCKER
	@printf "  $(C_CYAN)docker$(C_RESET)   Build the main g3 Docker image (ghcr.io/golismero/g3)\n"
	@printf "  $(C_CYAN)plugins$(C_RESET)  Build all plugin Docker images\n"
	@printf "  $(C_CYAN)pull$(C_RESET)     Pull g3 + all plugin images from ghcr.io\n"
else
	@printf "  $(C_DIM)docker             (disabled — Docker not detected)$(C_RESET)\n"
	@printf "  $(C_DIM)plugins            (disabled — Docker not detected)$(C_RESET)\n"
	@printf "  $(C_DIM)pull               (disabled — Docker not detected)$(C_RESET)\n"
endif

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
	sudo ln -s -f $$(pwd)/bin/g3tui /usr/bin/g3tui
	sudo ln -s -f $$(pwd)/bin/g3worker /usr/bin/g3worker
endif

# Update all Go module dependencies.
ifdef GO
update:
	cd src && $(MAKE) update
endif

# Target to build all that is buildable given the available toolchains.
ifdef GO
ifdef DOCKER
all: bin misc docker plugins
else
all: bin
endif
else
ifdef DOCKER
all: misc docker plugins
else
all: help
endif
endif

# Install the build requirements.
misc:
ifdef PYTHON
	python3 -m pip install -r misc/requirements.txt
endif

# Build the g3 Docker image.
docker:
ifdef PYTHON
	rm -f ./misc/deps.txt
ifdef GO
	cd src; for d in */; do cd "$$d"; go mod tidy; cd ..; done
endif
	./misc/collect-go-deps.py ./misc/deps.txt
else
	touch ./misc/deps.txt
endif
	docker build -t ghcr.io/golismero/g3 .

# Build all of the Docker images for the plugins.
ifdef DOCKER
ifdef GO
plugins:
	cd plugins && $(MAKE) all
	./bin/g3config
else
plugins: docker
	cd plugins && $(MAKE) all
	docker compose run g3config
endif
endif

# Pull the main g3 image and all plugin images from ghcr.io.
ifdef DOCKER
pull:
	docker pull ghcr.io/golismero/g3
	cd plugins && $(MAKE) pull
endif
