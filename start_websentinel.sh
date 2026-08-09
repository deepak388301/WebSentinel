#!/usr/bin/env bash
set -euo pipefail

PORT="${WEBSENTINEL_PORT:-8080}"
TARGET="${WEBSENTINEL_TARGET:-http://127.0.0.1:9000}"

# --- Pre-flight: fail fast if the port is already in use ---
if ss -tlnp "sport = :$PORT" 2>/dev/null | grep -q ":$PORT "; then
  echo "ERROR: Port $PORT is already in use — stop the other process first" >&2
  exit 1
fi

# --- Auto-apply database migrations (single source of truth for the schema) ---
echo "Applying database migrations..."
export FLASK_APP=proxy_app.py
if ! python -m flask db upgrade; then
  echo "ERROR: Database migration failed — refusing to start with a broken schema." >&2
  exit 1
fi

echo "Starting WebSentinel..."
echo "  Target:  $TARGET"
echo "  Proxy:   http://0.0.0.0:$PORT"
echo "  Dashboard: http://0.0.0.0:$PORT/websentinel/"
echo ""
echo "Press Ctrl+C to stop."

exec gunicorn --bind 0.0.0.0:"$PORT" proxy_app:app
