.PHONY: all pull
all: osvdb2cve.json
	docker build -t ghcr.io/golismero/nikto .
osvdb2cve.json:
	python3 ../../../misc/osvdb2cve.py
pull:
	docker pull ghcr.io/golismero/nikto
