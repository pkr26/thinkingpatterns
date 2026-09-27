# The backup worker shares the exact Postgres major version and immutable
# base-image digest used by docker-compose.yml.  Its two small utilities are
# installed while the image is built, never from the running backup loop: a
# scheduled backup must not depend on a live package-repository fetch before
# it can protect a database.
#
# Reproducibility note (2026-09-26 infra audit): `apk add` resolves against
# Alpine's LIVE repositories at build time, so two builds of the same digest
# can pick different package builds. Version-pinning apk packages trades
# that drift for guaranteed build breakage when the pinned versions leave
# the repo — the chosen trade is: base digest-pinned, packages floating,
# with CI's docker job building this image on every push so drift surfaces
# in CI rather than at a disaster-recovery rebuild.
FROM postgres:18-alpine@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873

USER root
RUN apk add --no-cache openssl python3
COPY backup_mac.py /usr/local/bin/mindpattern-backup-mac
RUN chmod 0755 /usr/local/bin/mindpattern-backup-mac \
    && mkdir -p /backups \
    && chown postgres:postgres /backups
USER postgres
