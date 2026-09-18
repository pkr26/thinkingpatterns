# The backup worker shares the exact Postgres major version and immutable
# base-image digest used by docker-compose.yml.  Its two small utilities are
# installed while the image is built, never from the running backup loop: a
# scheduled backup must not depend on a live package-repository fetch before
# it can protect a database.
FROM postgres:16-alpine@sha256:cf78e76683b9ca8c5733cbbdce6c9262b45b6767934dd0a95e671f9a0fc20685

USER root
RUN apk add --no-cache openssl python3
COPY backup_mac.py /usr/local/bin/mindpattern-backup-mac
RUN chmod 0755 /usr/local/bin/mindpattern-backup-mac \
    && mkdir -p /backups \
    && chown postgres:postgres /backups
USER postgres
