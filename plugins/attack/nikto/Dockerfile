# We need to use a Python image for the wrapper
FROM python:3-alpine

# Install Nikto
RUN apk update && \
    apk add --no-cache nikto perl-net-ssleay && \
    rm -f /tmp/* /etc/apk/cache/*

# Add the Golismero3 wrapper
RUN pip install --no-cache-dir -U lxml
WORKDIR /app/
COPY osvdb2cve.json /app/
COPY --chmod=0755 g3p.sh /usr/bin/g3p
COPY --chmod=0755 g3i.py /usr/bin/g3i
COPY --chmod=0755 g3m.py /usr/bin/g3m
ENTRYPOINT ["/usr/bin/g3p"]
