.PHONY: all bin dist clean docker plugins pull update install uninstall lint help

# Default target — show help when invoked as bare `make`.
.DEFAULT_GOAL := help

GO     := $(shell command -v go 2> /dev/null)
DOCKER := $(shell command -v docker 2> /dev/null)
PYTHON := $(shell command -v python3 2> /dev/null)

# Install prefix. /usr/local works on Linux (FHS-compliant), macOS Intel
# (Homebrew Intel), and macOS Apple Silicon (in default PATH via /etc/paths,
# sudo-writable, not SIP-protected). /usr/bin is wrong on macOS (SIP) and
# non-FHS on Linux. Apple Silicon Homebrew users who prefer that layout can
# override: `make install PREFIX=/opt/homebrew`.
PREFIX    ?= /usr/local
BINDIR    ?= $(PREFIX)/bin

# Binaries that get shell completions installed. The daemons have no flags.
CLI_BINS  := g3 g3cli g3tui

# System completion directories. Each is `-d`-gated at install time so missing
# shells are silently skipped. Bash has two Linux conventions (Debian vs
# Fedora/Arch) plus two macOS Homebrew layouts.
BASH_DIRS := /etc/bash_completion.d \
             /usr/share/bash-completion/completions \
             /usr/local/etc/bash_completion.d \
             /opt/homebrew/etc/bash_completion.d
ZSH_DIRS  := /usr/share/zsh/site-functions \
             /usr/local/share/zsh/site-functions \
             /opt/homebrew/share/zsh/site-functions
FISH_DIRS := /usr/share/fish/vendor_completions.d \
             /usr/local/share/fish/vendor_completions.d \
             /opt/homebrew/share/fish/vendor_completions.d

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
	@printf "  $(C_GREEN)Go$(C_RESET)        $(C_DIM)$(GO)$(C_RESET)\n"
else
	@printf "  $(C_RED)Go$(C_RESET)        $(C_DIM)not found — Go-only targets are disabled$(C_RESET)\n"
endif
ifdef DOCKER
	@printf "  $(C_GREEN)Docker$(C_RESET)    $(C_DIM)$(DOCKER)$(C_RESET)\n"
else
	@printf "  $(C_RED)Docker$(C_RESET)    $(C_DIM)not found — image targets will fail$(C_RESET)\n"
endif
ifdef PYTHON
	@printf "  $(C_GREEN)Python$(C_RESET)    $(C_DIM)$(PYTHON)$(C_RESET)\n"
else
	@printf "  $(C_RED)Python$(C_RESET)    $(C_DIM)not found — some targets may fail$(C_RESET)\n"
endif
	@printf "\n$(C_BOLD)Targets:$(C_RESET)\n"
	@printf "  $(C_CYAN)help$(C_RESET)      Show this message\n"
ifdef GO
ifdef DOCKER
	@printf "  $(C_CYAN)all$(C_RESET)       Build Go binaries and all Docker images\n"
else
	@printf "  $(C_CYAN)all$(C_RESET)       Build Go binaries $(C_DIM)(no Docker: images skipped)$(C_RESET)\n"
endif
	@printf "  $(C_CYAN)bin$(C_RESET)       Compile the Go binaries into ./bin/\n"
	@printf "  $(C_CYAN)dist$(C_RESET)      Cross-compile release zips + checksums into ./dist/ (version from git)\n"
	@printf "  $(C_CYAN)clean$(C_RESET)     Remove the compiled binaries and ./dist/\n"
	@printf "  $(C_CYAN)install$(C_RESET)   Symlink ./bin/g3* into $(BINDIR) and register shell completions (sudo; override PREFIX=...)\n"
	@printf "  $(C_CYAN)uninstall$(C_RESET) Remove the symlinks and completion files installed by 'make install'\n"
	@printf "  $(C_CYAN)update$(C_RESET)    Update all Go module dependencies\n"
	@printf "  $(C_CYAN)lint$(C_RESET)      Lint all Go code\n"
else
ifdef DOCKER
	@printf "  $(C_CYAN)all$(C_RESET)       Build all Docker images $(C_DIM)(no Go: bin/clean/install skipped)$(C_RESET)\n"
else
	@printf "  $(C_DIM)all       (disabled — Go and Docker not detected)$(C_RESET)\n"
endif
	@printf "  $(C_DIM)bin       (disabled — Go not detected)$(C_RESET)\n"
	@printf "  $(C_DIM)dist      (disabled — Go not detected)$(C_RESET)\n"
	@printf "  $(C_DIM)clean     (disabled — Go not detected)$(C_RESET)\n"
	@printf "  $(C_DIM)install   (disabled — Go not detected)$(C_RESET)\n"
	@printf "  $(C_DIM)uninstall (disabled — Go not detected)$(C_RESET)\n"
	@printf "  $(C_DIM)update    (disabled — Go not detected)$(C_RESET)\n"
	@printf "  $(C_DIM)lint      (disabled — Go not detected)$(C_RESET)\n"
endif
ifdef DOCKER
	@printf "  $(C_CYAN)docker$(C_RESET)    Build the main g3 Docker image (ghcr.io/golismero/g3)\n"
	@printf "  $(C_CYAN)plugins$(C_RESET)   Build all plugin Docker images\n"
	@printf "  $(C_CYAN)pull$(C_RESET)      Pull g3 + all plugin images from ghcr.io\n"
else
	@printf "  $(C_DIM)docker    (disabled — Docker not detected)$(C_RESET)\n"
	@printf "  $(C_DIM)plugins   (disabled — Docker not detected)$(C_RESET)\n"
	@printf "  $(C_DIM)pull      (disabled — Docker not detected)$(C_RESET)\n"
endif

# Build the binaries locally.
ifdef GO
bin:
	cd src && CGO_ENABLED=0 $(MAKE)
endif

# Cross-compile the release binaries into ./dist/ (zips + SHA-256 checksums),
# reproducing .github/workflows/release.yml. Version is derived from git
# (exact vX.Y.Z tag, else main->latest, else branch name, else dev). Requires
# `zip` and `sha256sum`/`shasum` on PATH.
ifdef GO
dist:
	./misc/build-dist.sh
endif

# Clean the locally built binaries and cross-compiled artifacts. Both bin/
# and dist/ keep a tracked self-ignoring .gitignore, so remove only the build
# output and leave those in place.
ifdef GO
clean:
	rm -f bin/g3*
	rm -f dist/g3-*
endif

# Install the binaries locally and register shell completions in system dirs.
ifdef GO
install:
	sudo ln -s -f $$(pwd)/bin/g3        $(BINDIR)/g3
	sudo ln -s -f $$(pwd)/bin/g3api     $(BINDIR)/g3api
	sudo ln -s -f $$(pwd)/bin/g3cli     $(BINDIR)/g3cli
	sudo ln -s -f $$(pwd)/bin/g3config  $(BINDIR)/g3config
	sudo ln -s -f $$(pwd)/bin/g3scanner $(BINDIR)/g3scanner
	sudo ln -s -f $$(pwd)/bin/g3tui     $(BINDIR)/g3tui
	sudo ln -s -f $$(pwd)/bin/g3worker  $(BINDIR)/g3worker
	@for bin in $(CLI_BINS); do \
	    for dir in $(BASH_DIRS); do \
	        [ -d $$dir ] && sudo sh -c "$(BINDIR)/$$bin completions bash > $$dir/$$bin" || true; \
	    done; \
	    for dir in $(ZSH_DIRS); do \
	        [ -d $$dir ] && sudo sh -c "$(BINDIR)/$$bin completions zsh  > $$dir/_$$bin" || true; \
	    done; \
	    for dir in $(FISH_DIRS); do \
	        [ -d $$dir ] && sudo sh -c "$(BINDIR)/$$bin completions fish > $$dir/$$bin.fish" || true; \
	    done; \
	done
endif

# Reverse `make install`: drop symlinks and any completion files we wrote.
ifdef GO
uninstall:
	sudo rm -f $(BINDIR)/g3        $(BINDIR)/g3api     $(BINDIR)/g3cli \
	           $(BINDIR)/g3config  $(BINDIR)/g3scanner $(BINDIR)/g3tui \
	           $(BINDIR)/g3worker
	@for bin in $(CLI_BINS); do \
	    for dir in $(BASH_DIRS); do sudo rm -f $$dir/$$bin; done; \
	    for dir in $(ZSH_DIRS);  do sudo rm -f $$dir/_$$bin; done; \
	    for dir in $(FISH_DIRS); do sudo rm -f $$dir/$$bin.fish; done; \
	done
endif

# Update all Go module dependencies.
ifdef GO
update:
	cd src && $(MAKE) update
ifdef PYTHON
	rm -f ./misc/deps.txt
	./misc/collect-go-deps.py ./misc/deps.txt
endif
endif

# Lint all Go code.
ifdef GO
lint:
	cd src && $(MAKE) lint
endif

# Target to build all that is buildable given the available toolchains.
ifdef GO
ifdef DOCKER
all: bin plugins docker
else
all: bin
endif
else
ifdef DOCKER
all: plugins docker
else
all: help
endif
endif

# Build all of the Docker images for the plugins.
ifdef DOCKER
ifdef GO
plugins:
	cd plugins && $(MAKE) all
	cd src && $(MAKE) ../bin/g3config
	./bin/g3config
else
plugins: docker
	cd plugins && $(MAKE) all
	docker compose run g3config
endif
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
	docker build --build-arg VERSION="$$(./misc/git-version.sh)" -t ghcr.io/golismero/g3 .

# Pull the main g3 image and all plugin images from ghcr.io.
ifdef DOCKER
pull:
	docker pull ghcr.io/golismero/g3
	cd plugins && $(MAKE) pull
endif
