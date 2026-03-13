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
COPY g3p.sh /usr/bin/g3p
RUN chmod +x /usr/bin/g3p
COPY g3i.py /usr/bin/g3i
RUN chmod +x /usr/bin/g3i
COPY g3m.py /usr/bin/g3m
RUN chmod +x /usr/bin/g3m
ENTRYPOINT ["/usr/bin/g3p"]
