# We need to use a Python image for the wrapper
FROM python:3-alpine

# Add the Golismero3 wrapper
RUN pip install --no-cache-dir -U redis vulners
WORKDIR /app
COPY cpe.db /app
#COPY mock.json /app
#COPY mock2.json /app
COPY --chmod=0755 g3p.py /usr/bin/g3p
COPY --chmod=0755 g3m.py /usr/bin/g3m
ENTRYPOINT ["/usr/bin/g3p"]
