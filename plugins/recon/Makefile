.PHONY: all pull nmap subfinder testssl untangle wafw00f

all: nmap subfinder testssl untangle wafw00f

pull:
	cd nmap && $(MAKE) pull
	cd subfinder && $(MAKE) pull
	cd testssl && $(MAKE) pull
	cd untangle && $(MAKE) pull
	cd wafw00f && $(MAKE) pull

nmap:
	cd nmap && $(MAKE) all

subfinder:
	cd subfinder && $(MAKE) all

testssl:
	cd testssl && $(MAKE) all

untangle:
	cd untangle && $(MAKE) all

wafw00f:
	cd wafw00f && $(MAKE) all
