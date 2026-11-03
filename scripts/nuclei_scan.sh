#!/usr/bin/env bash
# Vigía — Nuclei scan through Chrome proxy (WAF bypass).
#
# This is the SECOND command in the Vigía pipeline. Run it AFTER recon.sh
# has finished and you've reviewed the results. It launches a Chrome CDP
# proxy and runs Nuclei through it, so templates reach the real server
# even behind Akamai/Cloudflare.
#
# Usage:
#   docker compose run --rm -e BROWSER=chrome -e BROWSER_WS="$ws" \
#     nuclei-scan /scope/target.txt program-name [--rate-limit 5]
#
set -euo pipefail

cat <<'BANNER'

  ╔══════════════════════════════════════════════╗
  ║  Vigía — Nuclei Scan (Chrome WAF bypass)    ║
  ╚══════════════════════════════════════════════╝

BANNER

SCOPE="${1:-}"
PROGRAM="${2:-}"
RATE_LIMIT="${3:---rate-limit}"
RATE_VALUE="${4:-5}"

if [[ -z "$SCOPE" ]]; then
  cat <<'USAGE'
Usage:
  docker compose run --rm -e BROWSER=chrome -e BROWSER_WS="$ws" \
    nuclei-scan /scope/target.txt [program-name] [--rate-limit N]

Runs Nuclei through a Chrome CDP proxy to bypass WAF bot detection.
Requires the recon to have been run first (uses its alive_urls.txt + subs.txt).
USAGE
  exit 0
fi

[[ -f "$SCOPE" ]] || { echo "[!] scope file not found: $SCOPE" >&2; exit 1; }

# Defaults
HANDLE="${HANDLE:-researcher}"
CONTACT="${CONTACT:-}"
BROWSER="${BROWSER:-chrome}"
PROXY_PORT=8888

[[ -z "$PROGRAM" ]] && PROGRAM="$(basename "$SCOPE" | sed 's/\.[^.]*$//')"

# Find the latest recon run
LATEST="/data/${PROGRAM}/latest"
if [[ ! -L "$LATEST" ]]; then
  echo "[!] No recon run found for program '$PROGRAM'."
  echo "    Run the recon first:  docker compose run --rm recon /scope/... $PROGRAM"
  exit 1
fi
OUT="$(readlink -f "$LATEST")"
echo "[*] Using recon data from: $OUT"

# Build target list: alive URLs + resolved subdomains
TARGETS="$OUT/findings/nuclei-targets.txt"
cat "$OUT/alive_urls.txt" > "$TARGETS"
# Add subdomains as https:// URLs (catches dev/uat without WAF)
while read -r sub; do
  [[ -z "$sub" ]] && continue
  echo "https://${sub}"
done < "$OUT/subs.txt" >> "$TARGETS"
sort -u -o "$TARGETS" "$TARGETS"
TARGET_COUNT=$(wc -l < "$TARGETS")
echo "[*] Targets: $TARGET_COUNT URLs (alive + all subdomains)"

# Nuclei output dir
TS="$(date -u +%Y%m%d-%H%M%S)"
NUCLEI_OUT="$OUT/findings/nuclei-${TS}"
mkdir -p "$NUCLEI_OUT"

UA="bugbounty-${HANDLE}"
[[ -n "$CONTACT" ]] && UA="${UA} (+${CONTACT})"

if [[ "$BROWSER" == "chrome" ]] && [[ -n "${BROWSER_WS:-}" ]]; then
  echo "[*] Starting Chrome proxy on port $PROXY_PORT (rate: ${RATE_VALUE} req/s)..."

  # Start the Chrome proxy in background
  python3 /app/scripts/chrome_proxy.py \
    --ws "$BROWSER_WS" \
    --port "$PROXY_PORT" \
    --rate-limit "$RATE_VALUE" \
    --handle "$HANDLE" \
    --contact "$CONTACT" &
  PROXY_PID=$!

  # Wait for proxy to be ready
  for i in $(seq 1 15); do
    if curl -s "http://localhost:${PROXY_PORT}/" >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done

  if ! kill -0 "$PROXY_PID" 2>/dev/null; then
    echo "[!] Chrome proxy failed to start"
    exit 1
  fi
  echo "[*] Chrome proxy ready (PID $PROXY_PID)"

  PROXY_FLAG="-proxy http://localhost:${PROXY_PORT}"
else
  echo "[*] No Chrome proxy — running Nuclei direct (WAF may block)"
  PROXY_FLAG=""
  PROXY_PID=""
fi

echo "[*] Starting Nuclei scan..."
echo "    Output: $NUCLEI_OUT"
echo

# Run Nuclei with ALL templates, medium+high+critical
# shellcheck disable=SC2086
nuclei -l "$TARGETS" \
  -severity medium,high,critical \
  -H "User-Agent: ${UA}" \
  -H "X-Bug-Bounty: ${HANDLE}" \
  -rl "${RATE_VALUE}" \
  -c 5 \
  -timeout 15 \
  -retries 1 \
  $PROXY_FLAG \
  -o "$NUCLEI_OUT/results.txt" \
  -jsonl -je "$NUCLEI_OUT/results.jsonl" \
  -stats -si 30 \
  2>&1 || true

# Cleanup proxy
if [[ -n "${PROXY_PID:-}" ]]; then
  kill "$PROXY_PID" 2>/dev/null || true
  wait "$PROXY_PID" 2>/dev/null || true
fi

NUCLEI_COUNT=$(wc -l < "$NUCLEI_OUT/results.txt" 2>/dev/null || echo 0)

echo
echo "============================================"
echo "[+] Nuclei scan complete"
echo "============================================"
echo "    Targets scanned: $TARGET_COUNT"
echo "    Findings:        $NUCLEI_COUNT"
echo "    Results:         $NUCLEI_OUT/results.txt"
echo "    JSON:            $NUCLEI_OUT/results.jsonl"
echo
echo "    Share results with Mimir for analysis."
