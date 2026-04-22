# Official image.
FROM python:3-alpine

# Install python/pip and wafw00f.
ENV PYTHONUNBUFFERED=1
RUN apk add --update --no-cache python3 py3-pip && ln -sf python3 /usr/bin/python && \
    pip3 install --no-cache-dir --upgrade --root-user-action=ignore --break-system-packages wafw00f && \
    rm -f /tmp/* /etc/apk/cache/*

WORKDIR /app

# Add the Golismero3 wrapper.
COPY --chmod=0755 g3p.sh /usr/bin/g3p
COPY --chmod=0755 g3i.py /usr/bin/g3i

# Change the entrypoint to our wrapper.
ENTRYPOINT ["/usr/bin/g3p"]
