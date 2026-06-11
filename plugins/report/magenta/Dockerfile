# Official image.
FROM python:3-alpine

# Install git
RUN apk add --update --no-cache git

# Install magenta from sources.
WORKDIR /app
ENV PYTHONUNBUFFERED=1
RUN git clone https://github.com/golismero/magenta.git && \
    find magenta -name requirements.txt -exec python3 -m pip install \
        --no-cache-dir --root-user-action=ignore --break-system-packages \
        -r {} \;

# Add the Golismero3 wrapper.
COPY LICENSE /
COPY --chmod=0755 g3r.py /usr/bin/g3r

# Change the entrypoint to our wrapper.
ENTRYPOINT ["/usr/bin/g3r"]
