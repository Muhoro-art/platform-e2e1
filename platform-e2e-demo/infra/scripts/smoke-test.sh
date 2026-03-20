#!/usr/bin/env sh
set -e

API_URL="${API_URL:-http://localhost:4000}"

echo "Checking health..."
curl -f "$API_URL/health"

echo "Health OK"
