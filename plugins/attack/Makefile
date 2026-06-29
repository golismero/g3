.PHONY: all pull hydra nikto graphqlcop

all: hydra nikto graphqlcop

pull:
	cd hydra && $(MAKE) pull
	cd nikto && $(MAKE) pull
	cd graphqlcop && $(MAKE) pull

hydra:
	cd hydra && $(MAKE) all

nikto:
	cd nikto && $(MAKE) all

graphqlcop:
	cd graphqlcop && $(MAKE) all
