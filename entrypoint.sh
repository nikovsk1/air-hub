#!/bin/sh
set -e

DATA_DIR="${DATA_DIR:-/app/data}"
mkdir -p "$DATA_DIR"

if [ "$(id -u)" = "0" ]; then
  # SEC-05: SONOFF iHost bind-mount permissions recovery
  # If running as root, attempt to chown the data directory to non-root appuser (UID 10001)
  # and drop root privileges via gosu. If filesystem does not support chown (CIFS/FAT), continue gracefully.
  if chown -R appuser:appgroup "$DATA_DIR" 2>/dev/null; then
    exec gosu appuser "$@"
  else
    echo "[WARN] Cannot chown $DATA_DIR to appuser:appgroup, executing as current user" >&2
  fi
fi

exec "$@"
