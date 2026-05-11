.PHONY: all pull hydra nikto

all: hydra nikto

pull:
	cd hydra && $(MAKE) pull
	cd nikto && $(MAKE) pull

hydra:
	cd hydra && $(MAKE) all

nikto:
	cd nikto && $(MAKE) all
