# (inside action/entrypoint.sh, replace the existing SCAN_PATH/FAIL_ON lines)
# safe read of inputs: prefer underscore form, fall back to hyphen form via printenv
SCAN_PATH="$(printenv 'INPUT_PATH' || true)"
SCAN_PATH="${SCAN_PATH:-.}"

# Try the canonical underscore var, otherwise try the hyphenated variant.
FAIL_ON="$(printenv 'INPUT_FAIL_ON' || true)"
if [ -z "$FAIL_ON" ]; then
  FAIL_ON="$(printenv 'INPUT_FAIL-ON' || true)"
fi
FAIL_ON="${FAIL_ON:-high}"

echo "SlopGuard: scanning '$SCAN_PATH' (fail-on: $FAIL_ON)"
