# untangle is not on PyPI; clone and pin to a known-good commit.
# Debian (slim) rather than alpine so simphile installs from wheels.
FROM python:3-slim

ENV PYTHONUNBUFFERED=1

# git is needed to fetch untangle at build time.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

# Fetch and pin untangle (includes behavior_repository.out). Use "git -C" instead
# of "cd" so we avoid hadolint DL3003 without a WORKDIR-before-clone dance.
RUN git clone https://github.com/cemtopcuoglu/untangle.git /opt/untangle \
    && git -C /opt/untangle checkout ab877e54aee8d584a9477cc215d7a4e7c57df850

# Install untangle's Python dependencies (configargparse, simphile).
RUN pip3 install --no-cache-dir -r /opt/untangle/requirements.txt

# Add the Golismero3 wrapper and importer.
COPY --chmod=0755 g3p.sh /usr/bin/g3p
COPY --chmod=0755 g3i.py /usr/bin/g3i

# untangle reads behavior_repository.out from the CWD.
WORKDIR /opt/untangle

ENTRYPOINT ["/usr/bin/g3p"]
