# Pinned by digest (multi-arch manifest list, resolved 2026-09-07 via the
# Docker Hub registry API — Docker was unavailable locally, so this was
# verified against the registry, not a local cache). 3.14-slim is a mutable
# tag; the digest fixes the runtime base-image input.  It does NOT make the
# final image byte-identical: asyncpg is compiled from source below and that
# build still uses the builder image's apt repository and PEP-517 build
# dependencies. Dependabot (docker ecosystem, .github/dependabot.yml) will
# propose digest bumps as new 3.14-slim images publish.
FROM python:3.14-slim@sha256:cad9a2c871761c413caa6fdd6441c783451e740a48aaeba60ae62a8b53525ef6 AS wheels

WORKDIR /wheels

# asyncpg does not publish a CPython 3.14 wheel yet.  Build its verified
# source distribution in an isolated stage so a production image remains
# small and contains neither a compiler nor apt metadata.
COPY requirements.lock.txt ./
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && pip wheel --no-cache-dir --require-hashes --wheel-dir /wheels/out -r requirements.lock.txt \
    && apt-get purge -y --auto-remove build-essential \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

FROM python:3.14-slim@sha256:cad9a2c871761c413caa6fdd6441c783451e740a48aaeba60ae62a8b53525ef6

WORKDIR /srv

# The builder verifies every *runtime requirement* sdist/wheel against the
# locked upstream hashes before producing this private wheelhouse. Locally
# built wheels (notably asyncpg on CPython 3.14) necessarily have a NEW hash,
# so a second --require-hashes install would correctly reject them against the
# sdist hash. asyncpg's isolated PEP-517 build dependencies are upstream
# build inputs rather than entries in the runtime lock; this is therefore a
# hermetic final-stage install, not a claim of a bit-reproducible compiler
# build. Install only the builder's closed wheelhouse with no resolver;
# `pip check` verifies that its complete dependency graph was installed.
COPY requirements.lock.txt ./
COPY --from=wheels /wheels/out /wheels
RUN pip install --no-cache-dir --no-index --no-deps /wheels/*.whl \
    && pip check \
    && rm -rf /wheels requirements.lock.txt

COPY app ./app
# Migrations ship in the image: the entrypoint runs `alembic upgrade head`
# before starting uvicorn (see alembic/README.md); MINDPATTERN_DB_URL
# supplies the URL at runtime.
COPY alembic.ini ./
COPY alembic ./alembic
COPY docker-entrypoint.sh ./

# Run as an unprivileged user; the API never needs root.
RUN useradd --system --no-create-home --uid 10001 mindpattern
USER mindpattern

EXPOSE 8000

# Slim image has no curl; python + urllib is always present. Readiness, not
# liveness, is the container health signal: a live process with a failed
# database connection or an unapplied migration must be removed from service.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/readyz', timeout=4)"]

# --no-access-log (inside docker-entrypoint.sh): default access logs record
# every URL path (usernames on auth lookups) and every journal write/delete
# timestamp — exactly the "state-reconstructing" metadata this product
# promises not to keep. The username also moved out of the URL
# (POST /api/auth/salt) so proxies in front must be configured to not log
# request bodies either.
# Uvicorn proxy-header rewriting stays explicitly off, even behind a proxy:
# HardeningMiddleware must see the raw socket peer before it can decide
# whether MINDPATTERN_TRUSTED_PROXY_IPS authorizes forwarding metadata. Set
# MINDPATTERN_TRUST_PROXY_HEADERS=1 plus that exact direct-peer allowlist
# only for a controlled reverse-proxy topology; never use Uvicorn's
# --proxy-headers as a substitute.
# The entrypoint migrates first (`alembic upgrade head`) so the app never
# create_all-pre-creates an unstamped schema outside development.
CMD ["./docker-entrypoint.sh"]
