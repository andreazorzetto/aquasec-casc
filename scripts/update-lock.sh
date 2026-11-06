#!/bin/sh
# Regenerate requirements.lock from pyproject.toml, in the image's own base image.
# Versions already in the lock stay, unless pyproject.toml changes them. --upgrade
# moves everything to the latest.
#
#   scripts/update-lock.sh [--upgrade]
set -eu
cd "$(dirname "$0")/.."
base=$(sed -n 's/^ARG BASE_IMAGE=//p' Dockerfile)
exec docker run --rm --platform linux/amd64 --user "$(id -u):$(id -g)" -e HOME=/tmp \
    -v "$PWD:/repo" -w /repo "$base" sh -c '
python -m pip install -q --user --no-warn-script-location pip-tools
python - > /tmp/in.txt <<PY
import tomllib
p = tomllib.load(open("pyproject.toml", "rb"))
print("\n".join([*p["project"]["dependencies"], *p["build-system"]["requires"]]))
PY
/tmp/.local/bin/pip-compile -q "$@" --generate-hashes --allow-unsafe --strip-extras --no-header \
    --no-emit-index-url --no-annotate --output-file=requirements.lock /tmp/in.txt
' update-lock "$@"
