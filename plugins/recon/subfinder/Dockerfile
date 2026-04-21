# Official image.
FROM projectdiscovery/subfinder:latest

# Install python/pip.
ENV PYTHONUNBUFFERED=1
RUN apk add --update --no-cache python3 && ln -sf python3 /usr/bin/python && \
    python3 -m ensurepip && \
    pip3 install --no-cache-dir --upgrade --root-user-action=ignore --break-system-packages pip setuptools && \
    rm -f /tmp/* /etc/apk/cache/*

# Add the Golismero3 wrapper.
WORKDIR /app
COPY g3p.sh /usr/bin/g3p
RUN chmod +x /usr/bin/g3p
COPY g3i.py /usr/bin/g3i
RUN chmod +x /usr/bin/g3i

# Change the entrypoint to our wrapper.
ENTRYPOINT ["/usr/bin/g3p"]
