.PHONY: all pull
all: iana-descriptions.json
	docker build -t ghcr.io/golismero/nmap .
iana-descriptions.json:
	python3 ../../../misc/iana-descriptions.py
pull:
	docker pull ghcr.io/golismero/nmap
