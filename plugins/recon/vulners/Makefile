.PHONY: all pull
all: cpe.db
	docker build -t ghcr.io/golismero/vulners .
cpe.db:
	python3 ../../../misc/cpe-dictionary.py
pull:
	docker pull ghcr.io/golismero/vulners
