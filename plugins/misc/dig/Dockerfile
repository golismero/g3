# We need to use a Python image for the wrapper.
FROM python:3-alpine

# Install dig and jc (jc is pure Python, no build tools needed).
RUN apk add --no-cache bind-tools && \
    pip3 install --no-cache-dir --root-user-action=ignore --break-system-packages jc

# Add the Golismero3 wrapper.
COPY --chmod=0755 g3p.sh /usr/bin/g3p
COPY --chmod=0755 g3i.py /usr/bin/g3i

# Change the entrypoint to our wrapper.
ENTRYPOINT ["/usr/bin/g3p"]
