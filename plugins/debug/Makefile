.PHONY: all pull passthrough error force-exec

all: passthrough error force-exec

pull:
	cd passthrough && $(MAKE) pull
	cd error && $(MAKE) pull
	cd force-exec && $(MAKE) pull

passthrough:
	cd passthrough && $(MAKE) all

error:
	cd error && $(MAKE) all

force-exec:
	cd force-exec && $(MAKE) all
