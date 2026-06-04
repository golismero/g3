# We need a Python image for the wrapper scripts (g3p/g3i/g3m).
FROM python:3-alpine

# Pinned Nikto version, overridable for forks/testing.
ARG BUILD_VERSION=2.6.0
ARG NIKTO_URL=https://github.com/sullo/nikto.git

# Install Nikto 2.6.0 from source plus its Perl runtime dependencies.
# git is a build-only dep (virtual), removed after cloning. nikto.pl finds its
# plugins/databases/config via FindBin::RealBin, so the symlink onto PATH works.
RUN apk add --no-cache \
        perl \
        perl-net-ssleay \
        perl-json \
        perl-io-socket-ssl \
        perl-xml-writer \
        perl-mime-base64 \
        perl-xml-libxml \
    && apk add --no-cache --virtual .nikto-build git \
    && git clone --depth 1 --branch "${BUILD_VERSION}" "${NIKTO_URL}" /opt/nikto \
    && rm -rf /opt/nikto/.git \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto.pl \
    && apk del .nikto-build

# Add the Golismero3 Python wrapper.
RUN pip install --no-cache-dir -U lxml
WORKDIR /app/
COPY --chmod=0755 g3p.sh /usr/bin/g3p
ENTRYPOINT ["/usr/bin/g3p"]
