#!/usr/bin/env bash
# Vigía — recon orchestrator: enum -> alive -> crawl/screenshot/extract -> HTML report.
set -euo pipefail

SCOPE="${1:-}"
PROGRAM="${2:-}"

if [[ -z "$SCOPE" ]]; then
  cat <<'USAGE'
Vigía — containerized bug-bounty recon

Usage:
  docker compose up -d obscura
  docker compose run --rm recon ./scripts/recon.sh /scope/<file>.txt [program-name]

Output lands in ./data/<program>/<timestamp>/ with a browsable index.html
USAGE
  exit 0
fi

[[ -f "$SCOPE" ]] || { echo "[!] scope file not found: $SCOPE" >&2; exit 1; }

# Defaults (overridable via .env)
HANDLE="${HANDLE:-researcher}"
CONTACT="${CONTACT:-}"
CONCURRENCY="${CONCURRENCY:-5}"
HTTPX_RATELIMIT="${HTTPX_RATELIMIT:-50}"
AMASS_ENABLED="${AMASS_ENABLED:-true}"
AMASS_TIMEOUT_MIN="${AMASS_TIMEOUT_MIN:-10}"

[[ -z "$PROGRAM" ]] && PROGRAM="$(basename "$SCOPE" | sed 's/\.[^.]*$//')"
TS="$(date -u +%Y%m%d-%H%M%S)"
OUT="/data/${PROGRAM}/${TS}"
mkdir -p "$OUT/screenshots" "$OUT/crawl" "$OUT/findings"

# Normalise scope (strip comments/blanks)
grep -vE '^\s*(#|$)' "$SCOPE" | sed 's/\r$//' | sort -u > "$OUT/roots.txt"
echo "[*] Program: $PROGRAM   Roots: $(wc -l < "$OUT/roots.txt")   Out: $OUT"

echo "[*] Subdomain enumeration (passive)"
: > "$OUT/subs.raw"
subfinder -silent -dL "$OUT/roots.txt" >> "$OUT/subs.raw" 2>/dev/null || true

if [[ "$AMASS_ENABLED" == "true" ]]; then
  while read -r root; do
    [[ -z "$root" ]] && continue
    timeout "${AMASS_TIMEOUT_MIN}m" amass enum -passive -d "$root" -silent 2>/dev/null \
      >> "$OUT/subs.raw" || true
  done < "$OUT/roots.txt"
fi

cat "$OUT/roots.txt" >> "$OUT/subs.raw"
sort -u "$OUT/subs.raw" > "$OUT/subs.txt"
rm -f "$OUT/subs.raw"
echo "    -> $(wc -l < "$OUT/subs.txt") unique hosts"

echo "[*] Probing for live HTTP(S) services (httpx)"
UA="bugbounty-${HANDLE}"
[[ -n "$CONTACT" ]] && UA="${UA} (+${CONTACT})"
httpx -silent -l "$OUT/subs.txt" \
  -rl "$HTTPX_RATELIMIT" \
  -H "User-Agent: ${UA}" \
  -H "X-Bug-Bounty: ${HANDLE}" \
  -sc -title -td -ip -cl \
  -o "$OUT/alive.txt" 2>/dev/null || true

# Extract just the URLs for the crawler
grep -oE 'https?://[^ ]+' "$OUT/alive.txt" 2>/dev/null | sort -u > "$OUT/alive_urls.txt" || true
ALIVE_COUNT=$(wc -l < "$OUT/alive_urls.txt" 2>/dev/null || echo 0)
echo "    -> $ALIVE_COUNT live URLs"

if [[ "$ALIVE_COUNT" -eq 0 ]]; then
  echo "[!] No live hosts. Stopping (nothing to crawl)."
  exit 0
fi

echo "[*] Crawl + screenshot + JS extraction (Obscura via CDP)"
python3 /app/scripts/crawl_extract.py \
  --urls "$OUT/alive_urls.txt" \
  --out "$OUT" \
  --ws "${OBSCURA_WS:-ws://obscura:9222}" \
  --handle "$HANDLE" \
  --contact "$CONTACT" \
  --concurrency "$CONCURRENCY" \
  --delay-ms "${REQ_DELAY_MS:-400}" \
  --nav-timeout "${NAV_TIMEOUT_S:-25}"

# Stable pointer to the newest run
ln -sfn "$OUT" "/data/${PROGRAM}/latest"

echo
echo "[+] Done."
echo "    Report:    data/${PROGRAM}/${TS}/index.html   (also: data/${PROGRAM}/latest)"
echo "    Endpoints: data/${PROGRAM}/${TS}/findings/endpoints.txt"
echo "    Secrets:   data/${PROGRAM}/${TS}/findings/secrets.txt"
