.PHONY: all
all: cpe.db
	docker build -t golismero3/vulners .
cpe.db:
	python3 ../../../misc/cpe-dictionary.py