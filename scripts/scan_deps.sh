#!/usr/bin/env bash
echo "=== pip-audit ==="
pip-audit --strict 2>&1 || true
echo ""
echo "=== safety check ==="
safety check 2>&1 || true
