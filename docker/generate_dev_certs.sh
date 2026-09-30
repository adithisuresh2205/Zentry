#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# SentinelGate — Self-Signed TLS Certificate Generator
# For LOCAL DEVELOPMENT ONLY. Do NOT use in production.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

CERT_DIR="$(dirname "$0")/ssl"
mkdir -p "$CERT_DIR"

echo "▶ Generating self-signed TLS certificate for local development..."

openssl req -x509 \
    -newkey rsa:4096 \
    -keyout "$CERT_DIR/sentinelgate.key" \
    -out "$CERT_DIR/sentinelgate.crt" \
    -days 365 \
    -nodes \
    -subj "/C=US/ST=Dev/L=Dev/O=SentinelGate/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

chmod 600 "$CERT_DIR/sentinelgate.key"
chmod 644 "$CERT_DIR/sentinelgate.crt"

echo "✓ Certificate generated:"
echo "  Key:  $CERT_DIR/sentinelgate.key"
echo "  Cert: $CERT_DIR/sentinelgate.crt"
echo ""
echo "NOTE: Add the cert to your browser's trusted CAs to avoid TLS warnings."
echo "      Certificate fingerprint:"
openssl x509 -in "$CERT_DIR/sentinelgate.crt" -fingerprint -sha256 -noout
