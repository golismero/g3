# Based on https://github.com/instrumentisto/nmap-docker-image/
# Released on BlueOak-1.0.0 license: https://github.com/instrumentisto/nmap-docker-image/blob/main/LICENSE.md

# We need to use a Python image for the wrapper
FROM python:3-alpine

# Latest version of Nmap at the time of writing
ARG nmap_ver=7.99

# Install dependencies
RUN apk add --update --no-cache \
            ca-certificates \
            libpcap \
            libgcc libstdc++ \
            libssl3 \
 && update-ca-certificates \
 && rm -rf /var/cache/apk/*

# Compile and install Nmap from sources
# hadolint ignore=DL3003
RUN apk add --update --no-cache --virtual .build-deps \
        libpcap-dev lua-dev linux-headers openssl-dev \
        autoconf g++ libtool make \
        curl \
    \
 && curl -fL -o /tmp/nmap.tar.bz2 \
         https://nmap.org/dist/nmap-${nmap_ver}.tar.bz2 \
 && tar -xjf /tmp/nmap.tar.bz2 -C /tmp \
 && cd /tmp/nmap* \
 && ./configure \
        --prefix=/usr \
        --sysconfdir=/etc \
        --mandir=/usr/share/man \
        --infodir=/usr/share/info \
        --without-zenmap \
        --without-nmap-update \
        --with-openssl=/usr/lib \
        --with-liblua=/usr/include \
 && make \
 && make install \
    \
 && apk del .build-deps \
 && rm -rf /var/cache/apk/* \
           /tmp/nmap*

# Add the Golismero3 wrapper
WORKDIR /app
RUN pip install --no-cache-dir --root-user-action=ignore python-libnmap
COPY --chmod=0755 g3p.sh /usr/bin/g3p
COPY --chmod=0755 g3i.py /usr/bin/g3i
COPY --chmod=0755 g3m.py /usr/bin/g3m
COPY iana-descriptions.json .
ENTRYPOINT ["/usr/bin/g3p"]
