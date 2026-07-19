#!/usr/bin/env bash
set -euo pipefail

PORT="${WEBSENTINEL_PORT:-8443}"
CERT_PATH="${SSL_CERT_PATH:-cert.pem}"
KEY_PATH="${SSL_KEY_PATH:-key.pem}"
TARGET="${WEBSENTINEL_TARGET:-http://127.0.0.1:9000}"
MODE="${WEBSENTINEL_MODE:-detect}"

if [[ ! -f "$CERT_PATH" || ! -f "$KEY_PATH" ]]; then
  echo "Generating self-signed TLS certificate pair..."
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout "$KEY_PATH" -out "$CERT_PATH" -subj "/CN=localhost" >/dev/null 2>&1
fi

echo "Starting WebSentinel with Gunicorn HTTPS termination..."
echo "  Mode: $MODE"
echo "  Target: $TARGET"
echo "  HTTPS port: $PORT"

echo "  Certificate: $CERT_PATH"
echo "  Private key: $KEY_PATH"

WEBSENTINEL_TARGET="$TARGET" WEBSENTINEL_MODE="$MODE" \
exec gunicorn --certfile="$CERT_PATH" --keyfile="$KEY_PATH" --bind 0.0.0.0:"$PORT" proxy_app:app
