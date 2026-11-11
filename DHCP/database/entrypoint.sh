#!/bin/sh
set -e

# Start background sync daemon
/sync_daemon.sh &

# Execute official postgres entrypoint
exec /usr/local/bin/docker-entrypoint.sh "$@"
