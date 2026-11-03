#!/usr/bin/env bash
# Vigía — recon orchestrator: enum -> alive -> crawl/screenshot/extract -> HTML report.
set -euo pipefail

# Banner
cat <<'BANNER'

                                                       |
                .                                      |
                 '.                                  __|__
                   '.                               /_____\
                     '.____________________________/|  |  |\
                      /                            ||  |  ||
                     /                             ||__|__||
                    /                             /========\
                   /                              '==|  |=='
                                                     |\/|
  __     __  ___    ____   ___      _                 |/\|
  \ \   / / |_ _|  / ___| |_ _|    / \                |\/|
   \ \ / /   | |  | |  _   | |    / _ \               |/\|
    \ V /    | |  | |_| |  | |   / ___ \             /|  |\
     \_/    |___|  \____| |___| /_/   \_\           /_|__|_\
                                                  /        \
  ------------------------------------------    _/__________\_
  containerized bug-bounty recon              _/              \_
  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~/~~~~~~~~~~~~~~~~~~\~

                   github.com/KarasuJager/Vigia

BANNER

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

# Browser engine selection: obscura (default), playwright, or chrome (your real browser)
BROWSER="${BROWSER:-obscura}"
if [[ "$BROWSER" == "chrome" ]]; then
  CHROME_PORT="${CHROME_CDP_PORT:-9224}"
  # Docker Desktop (Windows/Mac): use host.docker.internal to reach the host
  # Linux with --network host: localhost works directly
  CHROME_HOST="host.docker.internal"
  if curl -s "http://localhost:${CHROME_PORT}/json/version" >/dev/null 2>&1; then
    CHROME_HOST="localhost"
  fi
  BROWSER_LABEL="Chrome real (tu navegador — bypasses any WAF)"
  # Verify Chrome is reachable
  if ! curl -s "http://${CHROME_HOST}:${CHROME_PORT}/json/version" >/dev/null 2>&1; then
    echo "[!] Chrome not found on port ${CHROME_PORT}."
    echo "    Launch it first:"
    echo "      chrome.exe --remote-debugging-port=${CHROME_PORT} --user-data-dir=\"\$HOME/vigia-chrome\""
    exit 1
  fi
  if [[ -z "$BROWSER_WS" ]]; then
    BROWSER_WS="http://${CHROME_HOST}:${CHROME_PORT}"
  fi
  echo "[*] Connected to Chrome -> ${BROWSER_WS}"
elif [[ "$BROWSER" == "playwright" ]]; then
  BROWSER_WS="http://localhost:9223"
  BROWSER_LABEL="Playwright Chromium (BoringSSL — WAF bypass)"
else
  BROWSER_WS="${OBSCURA_WS:-ws://localhost:9222}"
  BROWSER_LABEL="Obscura (rustls — fast, lightweight)"
fi

[[ -z "$PROGRAM" ]] && PROGRAM="$(basename "$SCOPE" | sed 's/\.[^.]*$//')"
TS="$(date -u +%Y%m%d-%H%M%S)"
OUT="/data/${PROGRAM}/${TS}"
mkdir -p "$OUT/screenshots" "$OUT/crawl" "$OUT/findings"

# Normalise scope (strip comments/blanks)
grep -vE '^\s*(#|$)' "$SCOPE" | sed 's/\r$//' | sort -u > "$OUT/roots.txt"
echo "[*] Program: $PROGRAM   Roots: $(wc -l < "$OUT/roots.txt")   Browser: $BROWSER   Out: $OUT"

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

# --- Out-of-scope exclusion (compliance): drop OOS hosts before probing ---
# Looks for a sibling "<scope>.exclude.txt" (one ERE pattern per line). If absent,
# behaviour is unchanged. Keeps active probing/crawling strictly in-scope.
EXCL="${SCOPE%.*}.exclude.txt"
if [[ -f "$EXCL" ]]; then
  _before=$(wc -l < "$OUT/subs.txt")
  grep -vEf "$EXCL" "$OUT/subs.txt" > "$OUT/subs.scoped" || true
  mv "$OUT/subs.scoped" "$OUT/subs.txt"
  cp "$EXCL" "$OUT/exclude.txt"
  echo "    -> excluded $(( _before - $(wc -l < "$OUT/subs.txt") )) out-of-scope host(s) ($(basename "$EXCL"))"
fi
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
HTTPX_COUNT=$(wc -l < "$OUT/alive_urls.txt" 2>/dev/null || echo 0)
echo "    -> $HTTPX_COUNT live URLs (httpx)"

# WAF fallback: root domains always get crawled even if httpx can't probe them
# (WAFs block raw HTTP probes but the browser engine passes with real TLS)
echo "[*] Adding root domains as WAF fallback (browser will validate)"
while read -r root; do
  [[ -z "$root" ]] && continue
  echo "https://${root}"
  # Only add www. prefix if the root doesn't already start with www.
  [[ "$root" != www.* ]] && echo "https://www.${root}"
done < "$OUT/roots.txt" >> "$OUT/alive_urls.txt"
sort -u -o "$OUT/alive_urls.txt" "$OUT/alive_urls.txt"
ALIVE_COUNT=$(wc -l < "$OUT/alive_urls.txt" 2>/dev/null || echo 0)
echo "    -> $ALIVE_COUNT total URLs (httpx + fallback)"

if [[ "$ALIVE_COUNT" -eq 0 ]]; then
  echo "[!] No live hosts. Stopping (nothing to crawl)."
  exit 0
fi

echo "[*] Crawl + screenshot + JS extraction ($BROWSER_LABEL)"
python3 /app/scripts/crawl_extract.py \
  --urls "$OUT/alive_urls.txt" \
  --out "$OUT" \
  --ws "$BROWSER_WS" \
  --handle "$HANDLE" \
  --contact "$CONTACT" \
  --concurrency "$CONCURRENCY" \
  --delay-ms "${REQ_DELAY_MS:-400}" \
  --nav-timeout "${NAV_TIMEOUT_S:-60}"

# Stable pointer to the newest run
ln -sfn "$OUT" "/data/${PROGRAM}/latest"

echo
echo "[+] Recon complete. Checking for source maps..."
echo

python3 /app/scripts/sourcemap_extract.py "$OUT" \
  --handle "$HANDLE" \
  --delay-ms "${REQ_DELAY_MS:-400}" \
  2>/dev/null || true

echo
echo "[+] Starting JS Deep Analysis..."
echo

python3 /app/scripts/js_analyze.py "$OUT" \
  --linkfinder /opt/LinkFinder/linkfinder.py \
  --secretfinder /opt/SecretFinder/SecretFinder.py \
  --jsluice /usr/local/bin/jsluice

echo
echo "[+] Starting Nuclei scan (critical + high)..."
echo

mkdir -p "$OUT/findings/nuclei"
nuclei -l "$OUT/alive_urls.txt" \
  -severity critical,high \
  -t cves/ -t exposed-panels/ -t misconfiguration/ -t default-logins/ \
  -H "User-Agent: ${UA}" \
  -H "X-Bug-Bounty: ${HANDLE}" \
  -rl 25 \
  -c 10 \
  -o "$OUT/findings/nuclei/results.txt" \
  -jsonl -je "$OUT/findings/nuclei/results.jsonl" \
  -silent 2>/dev/null || true

NUCLEI_COUNT=$(wc -l < "$OUT/findings/nuclei/results.txt" 2>/dev/null || echo 0)
echo "    -> $NUCLEI_COUNT findings (critical + high)"

echo
echo "============================================"
echo "[+] VIGÍA complete"
echo "============================================"
echo "    Report:     data/${PROGRAM}/${TS}/index.html"
echo "    Endpoints:  data/${PROGRAM}/${TS}/findings/endpoints.txt"
echo "    Secrets:    data/${PROGRAM}/${TS}/findings/secrets.txt"
echo "    Nuclei:     data/${PROGRAM}/${TS}/findings/nuclei/ ($NUCLEI_COUNT hits)"
echo "    JS raw:     data/${PROGRAM}/${TS}/findings/js-raw/"
echo "    JS analysis: data/${PROGRAM}/${TS}/findings/js-analysis/"
echo
echo "    Share results with Mimir for hypothesis generation."
