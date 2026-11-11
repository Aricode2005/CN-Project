FROM postgres:15-alpine

RUN apk add --no-cache curl jq

COPY init.sql /docker-entrypoint-initdb.d/init.sql
COPY sync_daemon.sh /sync_daemon.sh
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /sync_daemon.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["postgres"]
