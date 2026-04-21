FROM golang:1.25
ENV DEBIAN_FRONTEND=noninteractive
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN apt-get update -y && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends ca-certificates curl gnupg && \
    curl -fsSL https://get.docker.com | sh && \
    apt-get clean -y && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY ./misc/deps.txt /app/
# hadolint ignore=SC2046
RUN go mod download -x $(cat /app/deps.txt) && \
    rm /app/deps.txt
COPY src/ /app/
RUN CGO_ENABLED=0 GOOS=linux make && \
    go clean -modcache && \
    rm -fr /app/src
CMD [ "/bin/g3" ]