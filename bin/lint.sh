#!/usr/bin/env sh
. .venv/bin/activate

dirs="github_webhooks example"

echo "Running lint checks"

echo "Running pylint"
pylint $dirs

echo "Running mypy"
mypy $dirs
