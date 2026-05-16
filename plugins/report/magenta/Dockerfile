# Official image.
FROM python:3-alpine

# Install git
RUN apk add --update --no-cache git

# Install magenta from sources.
WORKDIR /app
ENV PYTHONUNBUFFERED=1
RUN git clone https://github.com/golismero/magenta.git && \
    cd magenta && \
    for r in $(find . -name requirements.txt); do python3 -m pip install -r requirements.txt; done

# Add the Golismero3 wrapper.
COPY --chmod=0755 g3r.sh /usr/bin/g3r

# Change the entrypoint to our wrapper.
ENTRYPOINT ["/usr/bin/g3r"]
