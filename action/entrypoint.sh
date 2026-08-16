#!/usr/bin/env bash
set -euo pipefail

# Example: read GitHub Actions inputs from env
path="${INPUT_PATH:-.}"
fail_on="${INPUT_FAIL_ON:-high}"
exclude="${INPUT_EXCLUDE:-}"

# TODO: run your scanner binary / script here
# Example placeholder:
echo "Running SlopGuard on path=$path exclude=$exclude fail_on=$fail_on"

# Exit 0 for now; replace with scanner exit status
exit 0
