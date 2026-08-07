# Official image.
FROM python:3-alpine

#ARG URL=https://github.com/santoru/shcheck
ARG URL=https://github.com/MarioVilas/shcheck.git

ENV PYTHONUNBUFFERED=1
WORKDIR /app

# Install shcheck.py from git.
RUN apk update \
    && apk add --no-cache git \
    && git clone --depth 1 $URL /app \
    && pip3 install setuptools \
    && python3 /app/setup.py install

# Add the Golismero3 wrapper.
COPY --chmod=0755 g3p.sh /usr/bin/g3p

# Change the entrypoint to our wrapper.
ENTRYPOINT ["/usr/bin/g3p"]
