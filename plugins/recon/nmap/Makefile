.PHONY: all
all: iana-descriptions.json
	docker build -t golismero3/nmap .
iana-descriptions.json:
	python3 ../../../misc/iana-descriptions.py