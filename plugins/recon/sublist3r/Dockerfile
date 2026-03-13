# We need to use a Python image for the wrapper.
FROM python:3-alpine

# Install Sublist3r from a fork that's known to work correctly.
# At the time of writing, the main repository is broken.
WORKDIR /app
RUN apk update && \
    apk add --no-cache git && \
    rm -f /tmp/* /etc/apk/cache/* && \
    git clone https://github.com/huntergregal/Sublist3r.git /app && \
    pip3 install --no-cache-dir --upgrade --root-user-action=ignore pip setuptools && \
    pip3 install --no-cache-dir --upgrade --root-user-action=ignore -r /app/requirements.txt && \
    python3 setup.py install

# Add the Golismero3 wrapper.
COPY g3p.py /usr/bin/g3p
RUN chmod +x /usr/bin/g3p
COPY g3i.py /usr/bin/g3i
RUN chmod +x /usr/bin/g3i

# Change the entrypoint to our wrapper.
ENTRYPOINT ["/usr/bin/g3p"]
