.PHONY: all
all: iana-descriptions.json
	docker build -t ghcr.io/golismero/nmap .
iana-descriptions.json:
	python3 ../../../misc/iana-descriptions.py