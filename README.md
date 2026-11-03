![Vigía — containerized bug-bounty recon](docs/banner.png)

# Vigía

> *El vigía otea desde la cofa y avisa de lo que aparece en el horizonte.*

Containerized, reproducible **bug-bounty recon + JS deep analysis**. Point it at
an in-scope root domain and get back: a browsable report with full-page
screenshots, endpoints and secrets from JavaScript, **plus a deep JS analysis**
with sink detection, hidden parameters, API routes, and vulnerable library
identification — all in a single command.

**Pipeline:**

```
subfinder + amass (passive)
  → httpx (probing) + WAF fallback (root domains always crawled)
  → browser engine via CDP (crawl + screenshot + JS download)
      Obscura (default) | Playwright Chromium | Your real Chrome
  → JS Deep Analysis (6 tools):
      1. js-beautify  — desminify
      2. built-in     — sinks, postMessage, auth flows, client-only validations, hidden params
      3. LinkFinder   — endpoint extraction
      4. SecretFinder — secret/token detection
      5. RetireJS     — vulnerable library detection
      6. JSLuice      — deep URL/secret/syntax-tree analysis
  → Nuclei (critical + high severity)
  → Source map extraction (when exposed)
  → HTML triage report + structured analysis output
```

---

## Why this over the usual `screenshot` scripts

- **It renders JavaScript.** A plain `curl`/`wget` sees an empty `<div id="root">`.
  Vigía drives a real browser over CDP, so it extracts API routes, hidden
  endpoints and secrets from the JS of heavy SPAs (React/Vue) — exactly where a lot
  of *info-disclosure* and *leaked-key* findings live.
- **Three browser engines.** Obscura for speed, Playwright for better TLS fingerprint,
  or your real Chrome to bypass any WAF. Pick the right tool for the target.
- **WAF-resilient.** Root domains are always added to the crawl list even if `httpx`
  can't probe them (WAFs block raw HTTP probes but the browser engine passes with
  real TLS). No more invisible targets behind Akamai/Cloudflare.
- **Deep JS analysis built-in.** Beyond simple regex extraction, Vigía runs 6 analysis
  tools on every downloaded JS file: it finds dangerous sinks (innerHTML, eval,
  postMessage without origin check), hidden API routes, client-only validations that
  can be bypassed, and known-vulnerable libraries.
- **Traffic is identified by default.** Every request carries a `User-Agent` and an
  `X-Bug-Bounty` header with your researcher handle. Many programs *require*
  identified traffic; Vigía complies out of the box.
- **No stealth, no evasion.** It deliberately runs **without** anti-detection flags.
  This is a tool for *authorized* testing.
- **Reproducible and unattended.** One command, fully containerized. Each run is
  timestamped; `latest` always points to the newest.

## Stack

| Layer | Tool |
|-------|------|
| Passive subdomain enum | [`subfinder`](https://github.com/projectdiscovery/subfinder) + [`amass`](https://github.com/owasp-amass/amass) |
| Live-host probing | [`httpx`](https://github.com/projectdiscovery/httpx) |
| Render / screenshot / crawl | **Obscura** (default), **Playwright Chromium**, or **your real Chrome** — all via CDP |
| Basic extraction | LinkFinder-style endpoint regex + secret patterns |
| JS desminification | [jsbeautifier](https://pypi.org/project/jsbeautifier/) |
| Endpoint extraction | [LinkFinder](https://github.com/dark-warlord14/LinkFinder) |
| Secret detection | [SecretFinder](https://github.com/m4ll0k/SecretFinder) |
| Vulnerable libraries | [RetireJS](https://retirejs.github.io/retire.js/) |
| Deep JS analysis | [JSLuice](https://github.com/BishopFox/jsluice) (compiled via multi-stage Docker build) |
| Vulnerability scanning | [Nuclei](https://github.com/projectdiscovery/nuclei) (critical + high) |
| Source maps | Built-in extractor (checks for exposed `.map` files) |
| Report | self-contained dark-theme `index.html` |

## Setup

```bash
git clone https://github.com/KarasuJager/vigia.git
cd vigia

cp .env.example .env          # set HANDLE (your researcher handle), tune throttling
docker compose build          # first build ~5-8 min (compiles JSLuice + downloads tools)
docker compose up -d obscura
```

## Browser Engines

Vigía supports three browser engines. Choose based on the target's defenses:

| Engine | `BROWSER=` | TLS fingerprint | WAF bypass | Speed | Use when |
|--------|-----------|----------------|------------|-------|----------|
| **Obscura** | `obscura` (default) | rustls | ❌ Blocked by advanced WAFs (Akamai, etc.) | ⚡ Fast | Targets without aggressive WAF |
| **Playwright** | `playwright` | BoringSSL (Chromium) | ⚠️ Some WAFs detect headless HTTP/2 | 🔄 Medium | Better TLS than Obscura, no Chrome needed |
| **Chrome** | `chrome` | Real Chrome (BoringSSL) | ✅ Bypasses any WAF | 🐢 Slower | Targets behind Akamai, Cloudflare, etc. |

### Using Obscura (default)

No extra setup needed. Obscura runs as a Docker service:

```bash
docker compose up -d obscura
docker compose run --rm recon /scope/target.txt program-name
```

### Using Playwright

Playwright runs as a separate Docker service with a real Chromium/BoringSSL stack:

```bash
# Build and start
docker compose build
docker compose up -d obscura   # still needed for the compose network

# Run with Playwright
docker compose run --rm -e BROWSER=playwright recon /scope/target.txt program-name
```

### Using your real Chrome (WAF bypass)

This connects Vigía to your actual Chrome browser — same TLS fingerprint, same cookies,
same everything. **No WAF can distinguish this from normal browsing.**

#### Step 1: Launch Chrome with remote debugging

```powershell
# Windows (PowerShell) — use a separate profile to avoid conflicts
chrome.exe --remote-debugging-port=9224 --user-data-dir="$HOME\vigia-chrome"
```

```bash
# macOS / Linux
google-chrome --remote-debugging-port=9224 --user-data-dir="$HOME/vigia-chrome"
```

#### Step 2: Set up port forwarding (Windows with Docker Desktop only)

Docker Desktop on Windows runs in a WSL2 VM. Chrome's CDP rejects WebSocket connections
with non-IP/non-localhost Host headers. The fix: forward through `netsh` using the
resolved IP:

```powershell
# One-time setup: forward port 9225 to Chrome on 9224
netsh interface portproxy add v4tov4 listenport=9225 listenaddress=0.0.0.0 connectport=9224 connectaddress=127.0.0.1
```

#### Step 3: Run VIGÍA with Chrome

```powershell
# Windows (PowerShell) — resolves the WebSocket URL automatically
$wsRaw = ((Invoke-WebRequest -Uri "http://localhost:9224/json/version" -UseBasicParsing).Content | ConvertFrom-Json).webSocketDebuggerUrl
$ip = [System.Net.Dns]::GetHostAddresses("host.docker.internal")[0].IPAddressToString
$ws = $wsRaw -replace "127.0.0.1:9224","${ip}:9225" -replace "localhost:9224","${ip}:9225"
docker compose run --rm -e BROWSER=chrome -e BROWSER_WS="$ws" recon /scope/target.txt program-name
```

```bash
# macOS / Linux with Docker Desktop
WS=$(curl -s http://localhost:9224/json/version | jq -r .webSocketDebuggerUrl)
IP=$(getent hosts host.docker.internal | awk '{print $1}')
WS=$(echo "$WS" | sed "s/127.0.0.1:9224/${IP}:9225/; s/localhost:9224/${IP}:9225/")
docker compose run --rm -e BROWSER=chrome -e BROWSER_WS="$WS" recon /scope/target.txt program-name
```

```bash
# Linux with --network host (no Docker Desktop)
# Chrome is on localhost — no port forwarding needed
docker compose run --rm -e BROWSER=chrome recon /scope/target.txt program-name
```

> **Why the IP dance?** Chrome's CDP security rejects WebSocket connections where the
> `Host` header is a hostname (like `host.docker.internal`). Using the resolved IP
> address makes Chrome see an IP in the Host header, which it accepts. The `netsh`
> proxy forwards port 9225 back to Chrome on localhost:9224.

#### Cleanup: remove port forwarding

```powershell
netsh interface portproxy delete v4tov4 listenport=9225 listenaddress=0.0.0.0
```

## Run

```bash
# Default (Obscura)
docker compose run --rm recon /scope/target.txt

# With a program name (organizes output under data/<program>/)
docker compose run --rm recon /scope/target.txt my-program

# With Playwright
docker compose run --rm -e BROWSER=playwright recon /scope/target.txt my-program

# With Chrome (see "Browser Engines" above for full setup)
docker compose run --rm -e BROWSER=chrome -e BROWSER_WS="$ws" recon /scope/target.txt my-program
```

Open the report:

```bash
# macOS/Linux
open  data/target/latest/index.html
# Windows (PowerShell)
start data\target\latest\index.html
```

## Output

```
data/<program>/<timestamp>/
├── subs.txt              all discovered subdomains
├── alive.txt             httpx output (status, title, tech, ip, content-length)
├── alive_urls.txt        live URLs (httpx + WAF fallback roots)
├── screenshots/*.png     full-page screenshots
├── crawl/<host>.json     links, scripts and every resource the page requested
├── findings/
│   ├── endpoints.txt      endpoints mined from JS  (-> feed into Burp)
│   ├── secrets.txt        potential secrets — verify manually
│   ├── js-raw/            raw JS files downloaded from the target
│   ├── js-analysis/       deep JS analysis output:
│   │   ├── beautified/        desminified JS (readable)
│   │   ├── builtin-analysis.txt   sinks, auth flows, hidden params, API routes
│   │   ├── api-routes.txt     API endpoints found in JS
│   │   ├── hidden-params.txt  potential hidden parameters
│   │   ├── linkfinder.txt     LinkFinder results
│   │   ├── secretfinder.txt   SecretFinder results
│   │   ├── retirejs.json      vulnerable libraries
│   │   └── jsluice.json       JSLuice URLs + secrets
│   └── nuclei/            Nuclei scan results (critical + high)
└── index.html            visual triage report
data/<program>/latest  ->  symlink to the newest run
```

### What the JS analysis finds

| Category | What it detects | Why it matters |
|----------|----------------|----------------|
| **XSS sinks** | innerHTML, eval, document.write, dangerouslySetInnerHTML, v-html, jQuery .html() | Direct XSS vectors |
| **postMessage** | message listeners without origin checks | Cross-origin data theft |
| **Prototype pollution** | \_\_proto\_\_, Object.assign, lodash merge | RCE in Node.js, XSS in browser |
| **Redirect sinks** | location.href, location.replace, window.open with variables | Open redirect chains |
| **Fetch sinks** | fetch/axios/XHR with variable URLs | SSRF vectors |
| **Auth flows** | Token storage, authorization headers, OAuth patterns, cookie manipulation | Auth bypass opportunities |
| **Client-only validation** | Disabled fields, readonly toggles, client-side role checks | Bypass from Burp |
| **Hidden parameters** | debug, test, admin, internal, force, bypass params in JS | Undocumented functionality |
| **API routes** | /api/, /v1/, /internal/, /admin/, /private/ paths in JS | Shadow API surface |
| **Vulnerable libraries** | Known CVEs in JS libraries (via RetireJS) | Known exploits |

## Tuning (`.env`)

| var | what | default |
|-----|------|---------|
| `HANDLE` | your researcher handle (sent to targets in UA + `X-Bug-Bounty`) | `your-handle` |
| `CONTACT` | optional contact appended to the User-Agent | *(empty)* |
| `BROWSER` | browser engine: `obscura`, `playwright`, or `chrome` | `obscura` |
| `BROWSER_WS` | override the WebSocket/HTTP endpoint for the browser | *(auto-detected)* |
| `CHROME_CDP_PORT` | Chrome remote debugging port (when `BROWSER=chrome`) | `9224` |
| `CONCURRENCY` | parallel pages during crawl/screenshot | `5` |
| `REQ_DELAY_MS` | delay added per request | `400` |
| `NAV_TIMEOUT_S` | per-page navigation timeout | `60` |
| `HTTPX_RATELIMIT` | httpx requests/sec cap | `50` |
| `AMASS_ENABLED` | run amass passive too | `true` |
| `AMASS_TIMEOUT_MIN` | cap amass passive per root | `10` |

## WAF Fallback

Some targets sit behind aggressive WAFs (Akamai Bot Manager, Cloudflare, etc.) that
block `httpx` probes entirely — making production sites invisible to the pipeline.

Vigía handles this automatically: **root domains from your scope file are always added
to the crawl list**, even if `httpx` can't reach them. The browser engine (especially
Chrome) will load these pages normally, bypassing the WAF's bot detection.

This means you'll see output like:

```
[*] Probing for live HTTP(S) services (httpx)
    -> 14 live URLs (httpx)
[*] Adding root domains as WAF fallback (browser will validate)
    -> 28 total URLs (httpx + fallback)
```

The fallback URLs are validated by the browser — if they're truly dead, they'll show
as errors in the report. No false positives.

## Responsible use

Vigía is for **authorized security testing only** — bug-bounty programs whose scope
and policy explicitly allow you to test, or systems you own or have written
permission to assess. Before you point it at anything:

- **Confirm scope.** Only roots the program lists. `scope/*.txt` is the only input.
- **Read the program's automation policy.** Some restrict automated crawling/scanning.
- **Read your host's AUP.** Many VPS/cloud providers prohibit scanning traffic.
- **Keep your traffic identified** (that's the default) and **throttle** for fragile
  targets — lower `CONCURRENCY`, raise `REQ_DELAY_MS`.

You are responsible for how you use this tool. The author assumes no liability for
misuse or for any damage caused. See [`LICENSE`](LICENSE).

## Browser Engines — Technical Details

### Obscura (default)

[Obscura](https://hub.docker.com/r/h4ckf0r0day/obscura) is a headless Chromium
accessible over CDP. It runs as a separate Docker service and shares its network
namespace with the recon container (CDP at `localhost:9222`).

- **Pros:** Fast, lightweight, no setup beyond `docker compose up -d obscura`
- **Cons:** Uses rustls for TLS — advanced WAFs (Akamai Bot Manager) fingerprint
  rustls vs BoringSSL and block it

### Playwright Chromium

A real Chromium browser running via Playwright inside Docker. Uses BoringSSL
(same TLS library as Chrome) for a better fingerprint than Obscura.

- **Pros:** Better TLS fingerprint, no Chrome install needed, fully containerized
- **Cons:** Headless — some WAFs detect headless Chromium via HTTP/2 protocol
  characteristics. Runs as a Docker service with `profiles: [playwright]`

### Chrome (your real browser)

Connects to your actual Chrome browser running on the host. The recon container
sends crawl commands over CDP to your Chrome — same TLS, same extensions, same
everything.

- **Pros:** Bypasses any WAF — indistinguishable from real browsing
- **Cons:** Requires Chrome with `--remote-debugging-port`, needs port forwarding
  on Docker Desktop (Windows/Mac), slightly slower

## Design notes

- Obscura runs **without** `--stealth` and its CDP port is **not** published to the
  host. If you ever expose it, bind to `127.0.0.1` and set `OBSCURA_CDP_TOKEN`.
- JS files are fetched server-side with the **same identified UA/header** as the crawl.
- JSLuice is compiled from source in a multi-stage Docker build (Go 1.22) — no
  prebuilt binary needed.
- One-shot by design: every run is timestamped and independent.
- The Chrome browser option resolves CDP WebSocket URLs automatically via the
  `/json/version` endpoint and replaces hostnames with IPs to satisfy Chrome's
  Host header security check.

---

Built by [Manuel Miguel Fernandez-Gallego Olivares](https://www.linkedin.com/in/manuel-miguel-olivares)
· Offensive Security Engineer · part of a small toolkit alongside
[SONDA](https://github.com/KarasuJager) (HTTP differential testing) and
bb-alert (new-program alerting).
