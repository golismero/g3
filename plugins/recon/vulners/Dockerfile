# We need to use a Python image for the wrapper
FROM python:3-alpine

# Add the Golismero3 wrapper
RUN pip install --no-cache-dir -U redis vulners
WORKDIR /app
COPY cpe.db /app
#COPY mock.json /app
#COPY mock2.json /app
COPY g3p.py /usr/bin/g3p
RUN chmod +x /usr/bin/g3p
COPY g3m.py /usr/bin/g3m
RUN chmod +x /usr/bin/g3m
ENTRYPOINT ["/usr/bin/g3p"]
