.PHONY: all attack debug misc recon pull help

# Default target — show help when invoked as bare `make`.
.DEFAULT_GOAL := help

DOCKER := $(shell command -v docker 2> /dev/null)
PYTHON := $(shell command -v python3 2> /dev/null)

# ANSI escape codes for the help target.
C_RESET := \033[0m
C_BOLD  := \033[1m
C_DIM   := \033[2m
C_RED   := \033[31m
C_GREEN := \033[32m
C_CYAN  := \033[36m

help:
	@printf "$(C_BOLD)Golismero 3$(C_RESET)\n\n"
	@printf "$(C_BOLD)Toolchain:$(C_RESET)\n"
ifdef DOCKER
	@printf "  $(C_GREEN)Docker$(C_RESET) $(C_DIM)$(DOCKER)$(C_RESET)\n"
else
	@printf "  $(C_RED)Docker$(C_RESET) $(C_DIM)not found — every target here will fail$(C_RESET)\n"
endif
ifdef PYTHON
	@printf "  $(C_GREEN)Python$(C_RESET) $(C_DIM)$(PYTHON)$(C_RESET)\n"
else
	@printf "  $(C_RED)Python$(C_RESET) $(C_DIM)not found — some targets will fail$(C_RESET)\n"
endif
	@printf "\n$(C_BOLD)Targets:$(C_RESET)\n"
	@printf "  $(C_CYAN)help$(C_RESET)     Show this message $(C_DIM)(default target)$(C_RESET)\n"
	@printf "  $(C_CYAN)all$(C_RESET)      Build every plugin Docker image\n"
	@printf "  $(C_CYAN)attack$(C_RESET)   Build the attack-category plugin images\n"
	@printf "  $(C_CYAN)debug$(C_RESET)    Build the debug-category plugin images\n"
	@printf "  $(C_CYAN)misc$(C_RESET)     Build the misc-category plugin images\n"
	@printf "  $(C_CYAN)recon$(C_RESET)    Build the recon-category plugin images\n"
	@printf "  $(C_CYAN)pull$(C_RESET)     Pull every plugin image from ghcr.io\n"

all: attack debug misc recon

pull:
	cd attack && $(MAKE) pull
	cd debug && $(MAKE) pull
	cd misc && $(MAKE) pull
	cd recon && $(MAKE) pull

attack:
	cd attack && $(MAKE) all

debug:
	cd debug && $(MAKE) all

misc:
	cd misc && $(MAKE) all

recon:
	cd recon && $(MAKE) all
