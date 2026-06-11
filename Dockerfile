FROM golang:latest AS builder
ENV DEBIAN_FRONTEND=noninteractive
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
WORKDIR /app
COPY ./misc/deps.txt /app/
RUN go mod download -x $(cat /app/deps.txt)
COPY src/ /app/
# VERSION is resolved on the host (where .git lives) and passed in by the
# `docker` make target; a bare `docker build` falls back to "dev". The flags
# mirror release.yml: strip symbols (-s -w), trim build paths (-trimpath),
# and stamp g3lib.Version.
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux make all \
      GO_FLAGS=-trimpath \
      GO_LDFLAGS="-s -w -X g3lib.Version=${VERSION}"
COPY plugins/ /app/plugins/
RUN mkdir -p /app/config && G3HOME=/app /bin/g3config

FROM debian:stable-slim
ENV DEBIAN_FRONTEND=noninteractive
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN apt-get update -y && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    install -m 0755 -d /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc && \
    chmod a+r /etc/apt/keyrings/docker.asc && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo $VERSION_CODENAME) stable" > /etc/apt/sources.list.d/docker.list && \
    apt-get update -y && \
    apt-get install -y --no-install-recommends docker-ce-cli && \
    apt-get clean -y && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /bin/g3 /bin/g3api /bin/g3cli /bin/g3config /bin/g3tui /bin/g3scanner /bin/g3worker /bin/
COPY --from=builder /app/config/g3plugins.json /etc/g3/
ENV G3_PLUGINS_CACHE_FILE=/etc/g3/g3plugins.json
CMD [ "/bin/g3" ]
