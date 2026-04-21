# Official image.
FROM python:3-alpine

# Install python/pip and git.
ENV PYTHONUNBUFFERED=1
RUN apk add --update --no-cache git python3 && ln -sf python3 /usr/bin/python && \
    python3 -m ensurepip && \
    pip3 install --no-cache-dir --upgrade --root-user-action=ignore --break-system-packages pip setuptools && \
    rm -f /tmp/* /etc/apk/cache/*

# Install wafw00f.
WORKDIR /app
RUN git clone https://github.com/EnableSecurity/wafw00f.git . && \
    python3 setup.py install

# Add the Golismero3 wrapper.
COPY g3p.sh /usr/bin/g3p
RUN chmod +x /usr/bin/g3p
COPY g3i.py /usr/bin/g3i
RUN chmod +x /usr/bin/g3i

# Change the entrypoint to our wrapper.
ENTRYPOINT ["/usr/bin/g3p"]
