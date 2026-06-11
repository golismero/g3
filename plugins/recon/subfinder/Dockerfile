# Official image.
FROM projectdiscovery/subfinder:latest

# Python 3 for the importer wrapper.
ENV PYTHONUNBUFFERED=1
RUN apk add --no-cache python3 coreutils

# Add the Golismero3 wrapper.
COPY LICENSE /
COPY --chmod=0755 g3p.sh /usr/bin/g3p
COPY --chmod=0755 g3i.py /usr/bin/g3i

# Change the entrypoint to our wrapper.
ENTRYPOINT ["/usr/bin/g3p"]
