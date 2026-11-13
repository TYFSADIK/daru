#!/usr/bin/env bash
# Run govulncheck and fail on any vulnerability Daru's code actually calls,
# except IDs listed in .govulncheck-allow after a written review.
#
# govulncheck has no suppression option, so this filters its JSON output.
# Each allowlist line is "<ID>  <reason>"; a line whose ID govulncheck no
# longer reports is flagged, so a stale exception is noticed and removed.
set -euo pipefail
cd "$(dirname "$0")/.."

allow_file=.govulncheck-allow
out=$(govulncheck -format json ./...)

# Symbol-level findings: the trace reaches a vulnerable function.
called=$(printf '%s' "$out" | jq -r 'select(.finding) | .finding | select(.trace[0].function != null) | .osv' | sort -u)
allowed=$(grep -v '^\s*#' "$allow_file" 2>/dev/null | awk 'NF {print $1}' | sort -u || true)

status=0
for id in $called; do
  if grep -qx "$id" <<<"$allowed"; then
    echo "allowed (reviewed): $id, see $allow_file"
  else
    echo "VULNERABLE: $id is reachable from Daru's code, https://pkg.go.dev/vuln/$id"
    status=1
  fi
done
for id in $allowed; do
  if ! grep -qx "$id" <<<"$called"; then
    echo "note: $id in $allow_file is no longer reported; remove it"
  fi
done
[ "$status" -eq 0 ] && echo "govulncheck: no unreviewed reachable vulnerabilities"
exit "$status"
