.PHONY: all pull nmap subfinder sublist3r testssl vulners wafw00f

all: nmap subfinder sublist3r testssl vulners wafw00f

pull:
	cd nmap && $(MAKE) pull
	cd subfinder && $(MAKE) pull
	cd sublist3r && $(MAKE) pull
	cd testssl && $(MAKE) pull
	cd vulners && $(MAKE) pull
	cd wafw00f && $(MAKE) pull

nmap:
	cd nmap && $(MAKE) all

subfinder:
	cd subfinder && $(MAKE) all

sublist3r:
	cd sublist3r && $(MAKE) all

testssl:
	cd testssl && $(MAKE) all

vulners:
	cd vulners && $(MAKE) all

wafw00f:
	cd wafw00f && $(MAKE) all
