# Using the official image as base.
FROM vanhauser/hydra:latest

# Switch to root to install more stuff.
USER root:root

# Need Python for the wrappers and Git for Magenta.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git python3 python3-pip \
    && apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install magenta from sources.
WORKDIR /app
ENV PYTHONUNBUFFERED=1
RUN git clone https://github.com/golismero/magenta.git && \
    find magenta -name requirements.txt -exec python3 -m pip install \
        --no-cache-dir --root-user-action=ignore --break-system-packages \
        -r {} \; && \
    python3 -m pip install -e . \
        --no-cache-dir --root-user-action=ignore --break-system-packages
ENV MAGENTA_HOME=/app

# Add the Golismero3 wrappers.
COPY --chmod=0755 g3i.py /usr/bin/g3i
COPY --chmod=0755 g3p.py /usr/bin/g3p

# Go back to the unprivileged user.
USER 10001:10001

# Change the entrypoint to our wrapper.
ENTRYPOINT ["/usr/bin/g3p"]
