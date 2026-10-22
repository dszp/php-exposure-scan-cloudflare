#!/usr/bin/env bash
# Run a scan against the deployed Worker with the service token in ./scan.env.
#   ./scan.sh [-f ndjson|json|csv] [file ...]   (reads stdin when no file is given)
# Input is anything with domains, URLs or email addresses in it, one or many per line.
set -euo pipefail
cd "$(dirname "$0")"
[[ -r scan.env ]] || { echo "scan.env missing; see scan.env.example" >&2; exit 1; }
# shellcheck disable=SC1091
source scan.env

format=ndjson
if [[ ${1:-} == -f ]]; then format=$2; shift 2; fi

# The token headers go in through a curl config on a file descriptor, not argv,
# so the secret never shows up in `ps`.
exec curl -sSN --fail-with-body "https://${SCAN_HOST}/scan?format=${format}" \
  -K <(printf 'header = "CF-Access-Client-Id: %s"\nheader = "CF-Access-Client-Secret: %s"\n' \
        "$CF_ACCESS_CLIENT_ID" "$CF_ACCESS_CLIENT_SECRET") \
  -H "X-Scan-Request: 1" -H "Content-Type: text/plain" \
  --data-binary @<(cat "$@")
