FROM alpine:3.17

WORKDIR /home/testssl

ARG BUILD_VERSION=3.2
ARG ARCHIVE_URL=https://github.com/drwetter/testssl.sh/archive/
ARG URL=https://github.com/drwetter/testssl.sh.git

# Install testssl.sh from git.
RUN test -n "${BUILD_VERSION}" \
    && apk update \
    && apk add --no-cache bash procps drill git coreutils libidn curl socat openssl xxd \
    && git clone --depth 1 --branch ${BUILD_VERSION} $URL /home/testssl \
    && addgroup testssl \
    && adduser -G testssl -g "testssl user" -s /bin/bash -D testssl \
    && ln -s /home/testssl/testssl.sh /usr/local/bin/ \
    && mkdir -p /home/testssl/etc /home/testssl/bin \
    && chmod 755 /home/testssl/etc /home/testssl/bin

# Install python/pip.
ENV PYTHONUNBUFFERED=1
RUN apk add --update --no-cache python3 && ln -sf python3 /usr/bin/python && \
    python3 -m ensurepip && \
    pip3 install --no-cache-dir --upgrade --root-user-action=ignore pip setuptools && \
    rm -f /tmp/* /etc/apk/cache/*

# Add the Golismero3 wrapper.
COPY g3p.py /usr/bin/g3p
RUN chmod +x /usr/bin/g3p
COPY g3i.py /usr/bin/g3i
RUN chmod +x /usr/bin/g3i
COPY g3m.py /usr/bin/g3m
RUN chmod +x /usr/bin/g3m

# Switch back to the non privileged user.
USER testssl

# Change the entrypoint to our wrapper.
ENTRYPOINT ["/usr/bin/g3p"]
