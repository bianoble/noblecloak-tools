#!/usr/bin/env bash
# Local reproduction of what CI runs -- see .github/workflows/ci-python.yml,
# ci-powershell.yml, and ci-parity.yml, which transcribe these same
# commands into GitHub Actions jobs. No pip installs, no npm installs:
# both languages' test runners are stdlib-only (unittest, Pester).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

echo "== Python unit + fixture-parity tests (tests/python) =="
python3 -m unittest discover -s tests/python -v

echo
echo "== Cross-language parity tests (tests/parity) =="
python3 -m unittest discover -s tests/parity -v

echo
if command -v pwsh >/dev/null 2>&1; then
    echo "== PowerShell tests (tests/powershell) =="
    pwsh -NoProfile -Command "Invoke-Pester -Path tests/powershell -CI"
else
    echo "== PowerShell tests (tests/powershell) skipped: pwsh not found on PATH =="
fi

echo
echo "All checks passed."
