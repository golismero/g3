FROM golang:1.25 AS builder
ENV DEBIAN_FRONTEND=noninteractive
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
WORKDIR /app
COPY ./misc/deps.txt /app/
RUN go mod download -x $(cat /app/deps.txt)
COPY src/ /app/
RUN CGO_ENABLED=0 GOOS=linux make all

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
COPY --from=builder /bin/g3 /bin/g3api /bin/g3cli /bin/g3config /bin/g3scanner /bin/g3worker /bin/
CMD [ "/bin/g3" ]
