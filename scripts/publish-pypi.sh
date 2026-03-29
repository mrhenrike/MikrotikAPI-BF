#!/bin/bash
# publish-pypi.sh — MikrotikAPI-BF PyPI publisher (Linux/macOS)
# Usage: PYPI_TOKEN=pypi-XXXX ./scripts/publish-pypi.sh
#        ./scripts/publish-pypi.sh --test  (TestPyPI)

set -e
cd "$(dirname "$0")/.."

TEST_MODE=false
[[ "$1" == "--test" ]] && TEST_MODE=true

echo "=== MikrotikAPI-BF PyPI Publisher ==="

if [[ -z "$PYPI_TOKEN" ]]; then
    echo "ERROR: Set PYPI_TOKEN env var: export PYPI_TOKEN=pypi-XXXX"
    exit 1
fi

# Clean + Build
rm -rf dist build *.egg-info
python -m build

# Check
python -m twine check dist/*

# Upload
export TWINE_USERNAME="__token__"
export TWINE_PASSWORD="$PYPI_TOKEN"

if $TEST_MODE; then
    python -m twine upload --repository-url https://test.pypi.org/legacy/ dist/* --non-interactive
    echo "Published to TestPyPI: pip install -i https://test.pypi.org/simple/ mikrotikapi-bf"
else
    python -m twine upload dist/* --non-interactive
    VER=$(python -c "from version import __version__; print(__version__)")
    echo ""
    echo "=== Published mikrotikapi-bf v${VER} to PyPI ==="
    echo "Install: pip install mikrotikapi-bf==${VER}"
    echo "URL: https://pypi.org/project/mikrotikapi-bf/${VER}/"
fi
