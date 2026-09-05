FROM python:3.14-slim

WORKDIR /srv

# Pinned runtime dependency set (generated from the tested environment;
# regenerate with: pip freeze | grep -E '^(fastapi|uvicorn|...)' > requirements.lock.txt).
COPY requirements.lock.txt ./
RUN pip install --no-cache-dir --no-deps -r requirements.lock.txt

COPY app ./app

# Run as an unprivileged user; the API never needs root.
RUN useradd --system --no-create-home --uid 10001 mindpattern
USER mindpattern

EXPOSE 8000
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
