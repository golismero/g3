# Python base — graphql-cop is a Python tool and our wrapper is Python too.
FROM python:3-alpine

WORKDIR /app

# Force Python to run in unbuffered mode to get real time logs.
ENV PYTHONUNBUFFERED=1

# Pinned graphql-cop version, overridable for forks/testing.
ARG BUILD_VERSION=1.16
ARG GRAPHQLCOP_URL=https://github.com/dolevf/graphql-cop.git

# Clone graphql-cop into /app and install its Python deps. git is a build-only
# dependency (virtual), removed after cloning along with the .git history.
RUN apk add --no-cache --virtual .build-deps git \
    && git clone --depth 1 --branch "${BUILD_VERSION}" "${GRAPHQLCOP_URL}" /app \
    && rm -rf /app/.git \
    && pip install --no-cache-dir -r requirements.txt \
    && apk del .build-deps

# Add the Golismero3 wrapper as the entrypoint.
COPY --chmod=0755 g3p.py /usr/bin/g3p
ENTRYPOINT ["/usr/bin/g3p"]
