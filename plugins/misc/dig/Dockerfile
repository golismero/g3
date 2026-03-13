# We need to use a Python image for the wrapper.
FROM python:3-alpine

# Install dig and jc.
RUN apk update && \
    apk add --no-cache bind-tools gcc libc-dev python3-dev && \
    rm -f /tmp/* /etc/apk/cache/* && \
    pip3 install --no-cache-dir --upgrade --root-user-action=ignore jc

# Add the Golismero3 wrapper.
COPY g3p.sh /usr/bin/g3p
RUN chmod +x /usr/bin/g3p
COPY g3i.py /usr/bin/g3i
RUN chmod +x /usr/bin/g3i

# Change the entrypoint to our wrapper.
ENTRYPOINT ["/usr/bin/g3p"]
