# Official image.
FROM python:3-alpine

# Install wafw00f (python3 and pip already in the base image).
ENV PYTHONUNBUFFERED=1
RUN pip3 install --no-cache-dir --root-user-action=ignore --break-system-packages wafw00f

WORKDIR /app

# Add the Golismero3 wrapper.
COPY --chmod=0755 g3p.sh /usr/bin/g3p
COPY --chmod=0755 g3i.py /usr/bin/g3i

# Change the entrypoint to our wrapper.
ENTRYPOINT ["/usr/bin/g3p"]
