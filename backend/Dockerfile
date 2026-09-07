# TODO(release): pin by digest (`FROM python:3.14-slim@sha256:…`) at release
# time — 3.14-slim is a mutable tag. (No registry access in the build
# environment this file was authored in, so no digest is recorded here.)
FROM python:3.14-slim

WORKDIR /srv

# Pinned runtime dependency set (generated from the tested environment;
# regenerate with: pip freeze | grep -E '^(fastapi|uvicorn|...)' > requirements.lock.txt).
COPY requirements.lock.txt ./
RUN pip install --no-cache-dir --no-deps -r requirements.lock.txt

COPY app ./app
# Migrations ship in the image so deploys can run `alembic upgrade head`
# (see alembic/README.md); MINDPATTERN_DB_URL supplies the URL at runtime.
COPY alembic.ini ./
COPY alembic ./alembic

# Run as an unprivileged user; the API never needs root.
RUN useradd --system --no-create-home --uid 10001 mindpattern
USER mindpattern

EXPOSE 8000

# Slim image has no curl; python + urllib is always present. /healthz is
# unauthenticated and returns no content metadata.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4)"]

# --no-access-log: default access logs record every URL path (usernames on
# auth lookups) and every journal write/delete timestamp — exactly the
# "state-reconstructing" metadata this product promises not to keep. The
# username also moved out of the URL (POST /api/auth/salt) so proxies in
# front must be configured to not log request bodies either.
# Direct exposure: no --proxy-headers, so uvicorn ignores X-Forwarded-For
# entirely and rate limiting always keys on the real peer address.
# Behind a reverse proxy run with:
#   --proxy-headers --forwarded-allow-ips <proxy-ip-or-cidr>
# (NOT "*": trusting every peer lets any client spoof its IP and evade
# rate limits) and set MINDPATTERN_TRUST_PROXY_HEADERS=1.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
