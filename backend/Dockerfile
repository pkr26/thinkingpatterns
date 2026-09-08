# TODO(release): pin by digest (`FROM python:3.14.x-slim@sha256:…`) at release
# time — 3.14-slim is a mutable tag. Docker was unavailable in the environment
# this file was authored in, so neither a patch tag nor a digest could be
# confirmed from a local cache; resolve with `docker buildx imagetools
# inspect python:3.14-slim` before the release build.
FROM python:3.14-slim

WORKDIR /srv

# Pinned runtime dependency set (generated from the tested environment;
# regenerate with: pip freeze | grep -E '^(fastapi|uvicorn|...)' > requirements.lock.txt).
COPY requirements.lock.txt ./
RUN pip install --no-cache-dir --no-deps -r requirements.lock.txt

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

# Slim image has no curl; python + urllib is always present. /healthz is
# unauthenticated and returns only {"status": "ok", "version": …} — no user
# or content metadata.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4)"]

# --no-access-log (inside docker-entrypoint.sh): default access logs record
# every URL path (usernames on auth lookups) and every journal write/delete
# timestamp — exactly the "state-reconstructing" metadata this product
# promises not to keep. The username also moved out of the URL
# (POST /api/auth/salt) so proxies in front must be configured to not log
# request bodies either.
# Direct exposure: no --proxy-headers, so uvicorn ignores X-Forwarded-For
# entirely and rate limiting always keys on the real peer address.
# Behind a reverse proxy run with:
#   --proxy-headers --forwarded-allow-ips <proxy-ip-or-cidr>
# (NOT "*": trusting every peer lets any client spoof its IP and evade
# rate limits) and set MINDPATTERN_TRUST_PROXY_HEADERS=1.
# The entrypoint migrates first (`alembic upgrade head`) so the app never
# create_all-pre-creates an unstamped schema outside development.
CMD ["./docker-entrypoint.sh"]
