#!/bin/sh
# Container entrypoint (PID 1): Railway mounts volumes as root, so a plain
# `USER app` image cannot write DATA_DIR on first boot.  Start as root, make
# the state directory writable by app, then drop privileges immediately and
# exec start.sh.  No root process stays resident.
#
# Resolution order for the state directory matches railway_manager.py:
#   $DATA_DIR -> $RAILWAY_VOLUME_MOUNT_PATH -> /app
set -eu

APP_UID=10001
APP_GID=10001

DATA_DIR="${DATA_DIR:-${RAILWAY_VOLUME_MOUNT_PATH:-/app}}"

if [ "$(id -u)" = "0" ]; then
  mkdir -p "$DATA_DIR"
  chown -R app:app "$DATA_DIR"

  # Dry run: perform the same privilege drop, then report the uid start.sh
  # would run as.  CI asserts this prints 10001.
  if [ "${ENTRYPOINT_DRY_RUN:-0}" = "1" ]; then
    exec python3 -c 'import os; os.setgroups([]); os.setgid(10001); os.setuid(10001); os.execvp("id", ["id", "-u"])'
  fi

  exec python3 -c 'import os; os.setgroups([]); os.setgid(10001); os.setuid(10001); os.execv("/app/start.sh", ["/app/start.sh"])'
fi

if [ "${ENTRYPOINT_DRY_RUN:-0}" = "1" ]; then
  exec id -u
fi

exec /app/start.sh
