#!/bin/bash
set -e

echo "Running smoke test..."

curl -f http://127.0.0.1:8000/health || exit 1

echo "Smoke test passed."
