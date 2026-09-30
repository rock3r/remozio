#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
python3 -m unittest discover -s tests -p 'test_*.py'
python3 -m unittest discover -s .agents/skills/babysit-pr/scripts -p 'test_*.py'
if [ "$(uname -s)" = Darwin ]; then
    swift build --package-path experiments/macos --triple arm64-apple-macosx26.0
fi
git diff --check
