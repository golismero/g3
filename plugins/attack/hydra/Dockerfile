# Using the official image as base.
FROM vanhauser/hydra:latest

# Switch to root to install more stuff.
USER root:root

# Need Python for the wrappers.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 python3-dev python3-pip \
    && apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Add the Golismero3 wrappers.
COPY --chmod=0755 g3p.py /usr/bin/g3p
COPY --chmod=0755 g3i.py /usr/bin/g3i
COPY --chmod=0755 g3m.py /usr/bin/g3m

# Go back to the unprivileged user.
USER 10001:10001

# Change the entrypoint to our wrapper.
ENTRYPOINT ["/usr/bin/g3p"]
