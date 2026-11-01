#!/usr/bin/env python3
"""
Vigía — crawl + screenshot + JS extraction + deep browser intelligence driver.

Connect to the headless browser over CDP, and for each live URL:
  - screenshot (full page)
  - collect links, <script src>, and every resource URL the page requested
  - capture API responses from network traffic (XHR/fetch)
  - extract localStorage and sessionStorage
  - detect WebSocket connections and messages
  - extract all forms with fields and actions
  - capture the full rendered DOM
  - fetch the JS files and regex out endpoints + likely secrets
Then build a browsable index.html.

Traffic is identified (User-Agent + X-Bug-Bounty header) and throttled.
No stealth / no evasion — this is authorized bug-bounty recon.
"""
import argparse, asyncio, json, re, sys
from pathlib import Path
from urllib.parse import urlparse

from playwright.async_api import async_playwright

# ---- extraction patterns ----------------------------------------------------

# LinkFinder-style endpoint regex (trimmed).
ENDPOINT_RE = re.compile(r"""
  (?:"|')(
    ((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})      # absolute URL
    | ((?:/|\.\./|\./)[^"'><,;|*()%$^/\\\[\]][^"'><,;|()]{1,})        # relative path
    | ([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[?|/][^"|']{0,}|))
    | ([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|js|action|html|xml)(?:\?[^"|']{0,}|))
  )(?:"|')
""", re.VERBOSE)

SECRET_PATTERNS = [
    ("AWS Access Key",   re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API Key",   re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Slack Token",      re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("Slack Webhook",    re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+")),
    ("GitHub Token",     re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}")),
    ("Stripe Live Key",  re.compile(r"sk_live_[0-9A-Za-z]{24,}")),
    ("JWT",              re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("Private Key",      re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("Generic Secret",   re.compile(r"""(?i)(?:api[_-]?key|secret|token|passwd|password|auth)["'\s:=]{1,6}["'][0-9A-Za-z\-_.]{12,}["']""")),
]

def safe_name(url: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", url)[:150]

# ---- per-host crawl ---------------------------------------------------------

async def crawl_one(browser, url, args, results, sem):
    async with sem:
        host_result = {"url": url, "status": None, "title": "", "screenshot": None,
                       "links": [], "scripts": [], "resources": [],
                       "api_responses": [], "storage": {}, "websockets": [],
                       "forms": [], "error": None}
        ua = f"bugbounty-{args.handle}" + (f" (+{args.contact})" if args.contact else "")
        resources = set()
        api_responses = []
        ws_messages = []

        try:
            ctx = await browser.new_context(
                user_agent=ua,
                extra_http_headers={"X-Bug-Bounty": args.handle},
                ignore_https_errors=True,
            )
            page = await ctx.new_page()

            # --- Network interception: capture API responses ---
            async def on_response(response):
                resources.add(response.url)
                ct = response.headers.get("content-type", "")
                # Capture JSON API responses (XHR/fetch)
                if "json" in ct or "/api/" in response.url or "/rest/" in response.url:
                    try:
                        body = await response.text()
                        if len(body) < 50000:  # cap to avoid huge responses
                            api_responses.append({
                                "url": response.url,
                                "status": response.status,
                                "content_type": ct[:100],
                                "body_preview": body[:2000],
                                "headers": {k: v for k, v in response.headers.items()
                                           if k.lower() in ("set-cookie", "x-csrf-token",
                                              "x-request-id", "x-powered-by", "server",
                                              "access-control-allow-origin",
                                              "content-security-policy", "x-frame-options")}
                            })
                    except Exception:
                        pass

            page.on("response", on_response)

            # --- WebSocket detection ---
            def on_websocket(ws):
                ws_info = {"url": ws.url, "messages": []}
                def on_msg(msg):
                    ws_info["messages"].append({
                        "type": "received",
                        "data": str(msg)[:500]
                    })
                def on_sent(msg):
                    ws_info["messages"].append({
                        "type": "sent",
                        "data": str(msg)[:500]
                    })
                ws.on("framereceived", on_msg)
                ws.on("framesent", on_sent)
                ws_messages.append(ws_info)

            page.on("websocket", on_websocket)

            # --- Navigate ---
            resp = await page.goto(url, wait_until="load", timeout=args.nav_timeout * 1000)
            host_result["status"] = resp.status if resp else None
            host_result["title"] = (await page.title()) or ""

            # Wait a bit for async API calls and WebSocket connections
            await asyncio.sleep(2)

            # --- Screenshot ---
            shot = f"screenshots/{safe_name(url)}.png"
            try:
                await page.screenshot(path=str(Path(args.out) / shot), full_page=True)
                host_result["screenshot"] = shot
            except Exception:
                pass

            # --- Links and scripts ---
            anchors = await page.eval_on_selector_all(
                "a[href]", "els => els.map(e => e.href)")
            scripts = await page.eval_on_selector_all(
                "script[src]", "els => els.map(e => e.src)")
            host_result["links"] = sorted(set(anchors))[:2000]
            host_result["scripts"] = sorted(set(scripts))
            host_result["resources"] = sorted(resources)[:3000]

            # --- Extract localStorage and sessionStorage ---
            try:
                storage = await page.evaluate("""() => {
                    const result = { localStorage: {}, sessionStorage: {} };
                    try {
                        for (let i = 0; i < localStorage.length; i++) {
                            const key = localStorage.key(i);
                            result.localStorage[key] = localStorage.getItem(key).substring(0, 500);
                        }
                    } catch(e) {}
                    try {
                        for (let i = 0; i < sessionStorage.length; i++) {
                            const key = sessionStorage.key(i);
                            result.sessionStorage[key] = sessionStorage.getItem(key).substring(0, 500);
                        }
                    } catch(e) {}
                    return result;
                }""")
                host_result["storage"] = storage
            except Exception:
                pass

            # --- Extract forms ---
            try:
                forms = await page.evaluate("""() => {
                    return Array.from(document.querySelectorAll('form')).map(f => ({
                        action: f.action || '',
                        method: (f.method || 'GET').toUpperCase(),
                        id: f.id || '',
                        name: f.name || '',
                        fields: Array.from(f.elements).filter(e => e.tagName !== 'BUTTON').map(e => ({
                            type: e.type || '',
                            name: e.name || '',
                            id: e.id || '',
                            value: e.type === 'password' ? '[REDACTED]' : (e.value || '').substring(0, 100),
                            required: e.required || false,
                            hidden: e.type === 'hidden',
                            placeholder: e.placeholder || ''
                        })).slice(0, 50)
                    })).slice(0, 20);
                }""")
                host_result["forms"] = forms
            except Exception:
                pass

            # --- Capture rendered DOM ---
            try:
                dom_dir = Path(args.out) / "dom"
                dom_dir.mkdir(parents=True, exist_ok=True)
                dom_content = await page.content()
                (dom_dir / f"{safe_name(url)}.html").write_text(dom_content, errors="replace")
            except Exception:
                pass

            # --- Extract event listeners (postMessage, etc.) ---
            try:
                listeners = await page.evaluate("""() => {
                    const result = { postMessage: false, serviceWorker: false, eventListeners: [] };
                    // Check for message event listeners (rough detection via override)
                    try {
                        const origAdd = EventTarget.prototype.addEventListener;
                        result.postMessage = document.body.innerHTML.includes('addEventListener') &&
                            document.body.innerHTML.includes("message");
                    } catch(e) {}
                    // Service worker
                    try {
                        result.serviceWorker = !!navigator.serviceWorker.controller;
                    } catch(e) {}
                    return result;
                }""")
                host_result["listeners"] = listeners
            except Exception:
                pass

            # --- Store API responses and WebSocket data ---
            host_result["api_responses"] = api_responses[:100]
            host_result["websockets"] = ws_messages[:20]

            await ctx.close()
        except Exception as e:
            host_result["error"] = str(e)[:300]

        (Path(args.out) / "crawl" / f"{safe_name(url)}.json").write_text(
            json.dumps(host_result, indent=2))
        results.append(host_result)
        tag = host_result["status"] or host_result["error"] or "?"

        # Summary line with new intel
        extras = []
        if api_responses: extras.append(f"{len(api_responses)} api")
        if host_result.get("forms"): extras.append(f"{len(host_result['forms'])} forms")
        if ws_messages: extras.append(f"{len(ws_messages)} ws")
        storage_keys = len(host_result.get("storage", {}).get("localStorage", {})) + \
                       len(host_result.get("storage", {}).get("sessionStorage", {}))
        if storage_keys: extras.append(f"{storage_keys} storage")
        extra_str = f" ({', '.join(extras)})" if extras else ""
        print(f"    [{tag}] {url}{extra_str}", flush=True)
        await asyncio.sleep(args.delay_ms / 1000)

# ---- JS endpoint / secret extraction ----------------------------------------

async def extract_js(browser, results, args):
    js_urls = set()
    for r in results:
        for u in r["scripts"] + r["resources"]:
            if u.split("?")[0].lower().endswith(".js"):
                js_urls.add(u)
    print(f"[*] Extracting from {len(js_urls)} JS files", flush=True)

    endpoints, secrets = {}, []
    ua = f"bugbounty-{args.handle}" + (f" (+{args.contact})" if args.contact else "")
    ctx = await browser.new_context(user_agent=ua,
                                    extra_http_headers={"X-Bug-Bounty": args.handle},
                                    ignore_https_errors=True)
    req = ctx.request
    sem = asyncio.Semaphore(args.concurrency)

    async def pull(js):
        async with sem:
            try:
                resp = await req.get(js, timeout=args.nav_timeout * 1000)
                body = await resp.text()
            except Exception:
                return
            # Save raw JS to disk for external analysis tools
            js_raw_dir = Path(args.out) / "findings" / "js-raw"
            js_raw_dir.mkdir(parents=True, exist_ok=True)
            js_filename = safe_name(js) + ".js"
            (js_raw_dir / js_filename).write_text(body, errors="replace")
            for m in ENDPOINT_RE.finditer(body):
                ep = m.group(1).strip("\"'")
                if 1 < len(ep) < 250:
                    endpoints.setdefault(ep, set()).add(js)
            for label, pat in SECRET_PATTERNS:
                for sm in pat.finditer(body):
                    secrets.append({"type": label, "match": sm.group(0)[:120], "source": js})
            await asyncio.sleep(args.delay_ms / 1000)

    await asyncio.gather(*(pull(j) for j in js_urls))
    await ctx.close()

    ep_lines = [f"{ep}\t<- {sorted(srcs)[0]}" for ep, srcs in sorted(endpoints.items())]
    (Path(args.out) / "findings" / "endpoints.txt").write_text("\n".join(ep_lines))
    sec_lines = [f"[{s['type']}] {s['match']}  ({s['source']})" for s in secrets]
    (Path(args.out) / "findings" / "secrets.txt").write_text("\n".join(sec_lines))
    print(f"    -> {len(endpoints)} endpoints, {len(secrets)} potential secrets", flush=True)
    return len(endpoints), secrets

# ---- browser intelligence summary -------------------------------------------

def write_browser_intel(results, out):
    """Write structured browser intelligence files from crawl data."""
    intel_dir = out / "findings" / "browser-intel"
    intel_dir.mkdir(parents=True, exist_ok=True)

    # API responses
    all_api = []
    for r in results:
        for api in r.get("api_responses", []):
            api["host"] = r["url"]
            all_api.append(api)
    if all_api:
        (intel_dir / "api-responses.json").write_text(json.dumps(all_api, indent=2))
        # Summary text
        api_summary = [f"# API Responses captured during crawl ({len(all_api)} total)\n"]
        for a in all_api:
            api_summary.append(f"[{a['status']}] {a['url']}")
            for hdr, val in a.get("headers", {}).items():
                api_summary.append(f"  {hdr}: {val}")
            if a.get("body_preview"):
                api_summary.append(f"  body: {a['body_preview'][:200]}")
            api_summary.append("")
        (intel_dir / "api-responses.txt").write_text("\n".join(api_summary))
        print(f"    -> {len(all_api)} API responses captured")

    # Storage (localStorage + sessionStorage)
    all_storage = {}
    for r in results:
        storage = r.get("storage", {})
        ls = storage.get("localStorage", {})
        ss = storage.get("sessionStorage", {})
        if ls or ss:
            all_storage[r["url"]] = {"localStorage": ls, "sessionStorage": ss}
    if all_storage:
        (intel_dir / "storage.json").write_text(json.dumps(all_storage, indent=2))
        storage_summary = ["# Browser Storage (localStorage + sessionStorage)\n"]
        for host, data in all_storage.items():
            storage_summary.append(f"## {host}")
            for store_type in ["localStorage", "sessionStorage"]:
                items = data.get(store_type, {})
                if items:
                    storage_summary.append(f"  {store_type}:")
                    for k, v in items.items():
                        storage_summary.append(f"    {k} = {v[:100]}")
            storage_summary.append("")
        (intel_dir / "storage.txt").write_text("\n".join(storage_summary))
        total_keys = sum(len(d.get("localStorage", {})) + len(d.get("sessionStorage", {}))
                        for d in all_storage.values())
        print(f"    -> {total_keys} storage keys across {len(all_storage)} hosts")

    # WebSockets
    all_ws = []
    for r in results:
        for ws in r.get("websockets", []):
            ws["host"] = r["url"]
            all_ws.append(ws)
    if all_ws:
        (intel_dir / "websockets.json").write_text(json.dumps(all_ws, indent=2))
        ws_summary = [f"# WebSocket connections ({len(all_ws)} total)\n"]
        for ws in all_ws:
            ws_summary.append(f"WS: {ws['url']} (from {ws['host']})")
            for msg in ws.get("messages", [])[:10]:
                ws_summary.append(f"  [{msg['type']}] {msg['data'][:200]}")
            ws_summary.append("")
        (intel_dir / "websockets.txt").write_text("\n".join(ws_summary))
        print(f"    -> {len(all_ws)} WebSocket connections detected")

    # Forms
    all_forms = []
    for r in results:
        for form in r.get("forms", []):
            form["host"] = r["url"]
            all_forms.append(form)
    if all_forms:
        (intel_dir / "forms.json").write_text(json.dumps(all_forms, indent=2))
        forms_summary = [f"# Forms ({len(all_forms)} total)\n"]
        for f in all_forms:
            forms_summary.append(f"[{f['method']}] {f['action']} (from {f['host']})")
            for field in f.get("fields", []):
                marker = "🔒" if field.get("hidden") else "  "
                req = " *" if field.get("required") else ""
                forms_summary.append(f"  {marker} {field['type']:10} name={field['name']}{req}")
            forms_summary.append("")
        (intel_dir / "forms.txt").write_text("\n".join(forms_summary))
        print(f"    -> {len(all_forms)} forms with {sum(len(f.get('fields',[])) for f in all_forms)} fields")

    return len(all_api), len(all_storage), len(all_ws), len(all_forms)

# ---- report -----------------------------------------------------------------

def build_report(results, out, n_endpoints, secrets, browser_intel=None):
    cards = []
    for r in sorted(results, key=lambda x: (x["status"] or 0)):
        shot = (f'<img loading="lazy" src="{r["screenshot"]}">'
                if r["screenshot"] else '<div class="noshot">no screenshot</div>')
        status = r["status"] or r["error"] or "?"
        title = (r["title"] or "").replace("<", "&lt;")[:120]
        # Extra badges
        badges = []
        if r.get("api_responses"): badges.append(f"{len(r['api_responses'])} api")
        if r.get("forms"): badges.append(f"{len(r['forms'])} forms")
        if r.get("websockets"): badges.append(f"{len(r['websockets'])} ws")
        badge_str = f" · {'  '.join(badges)}" if badges else ""
        cards.append(f"""<div class="card">
  <a href="{r['url']}" target="_blank" rel="noreferrer">{shot}</a>
  <div class="meta"><span class="st s{str(status)[:1]}">{status}</span>
  <a href="{r['url']}" target="_blank" rel="noreferrer">{r['url']}</a></div>
  <div class="title">{title}</div>
  <div class="counts">{len(r['scripts'])} js · {len(r['links'])} links{badge_str} ·
  <a href="crawl/{safe_name(r['url'])}.json">json</a></div>
</div>""")
    sec_preview = "".join(
        f"<li><b>{s['type']}</b>: <code>{s['match'].replace('<','&lt;')}</code></li>"
        for s in secrets[:50]) or "<li>none</li>"

    intel_str = ""
    if browser_intel:
        n_api, n_storage, n_ws, n_forms = browser_intel
        intel_parts = []
        if n_api: intel_parts.append(f"{n_api} API responses")
        if n_storage: intel_parts.append(f"{n_storage} hosts with storage")
        if n_ws: intel_parts.append(f"{n_ws} WebSocket connections")
        if n_forms: intel_parts.append(f"{n_forms} forms")
        if intel_parts:
            intel_str = f" · browser intel: {', '.join(intel_parts)}"

    html = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Vigía — {out.name}</title><style>
:root{{color-scheme:dark}}
body{{margin:0;background:#0d1117;color:#e6edf3;font:14px/1.5 system-ui,sans-serif}}
header{{padding:18px 20px;border-bottom:1px solid #30363d;position:sticky;top:0;background:#0d1117}}
h1{{font-size:16px;margin:0 0 4px}} .sub{{color:#8b949e;font-size:13px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:14px;padding:16px}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:10px;overflow:hidden}}
.card img{{width:100%;height:180px;object-fit:cover;object-position:top;display:block;background:#0d1117}}
.noshot{{height:180px;display:flex;align-items:center;justify-content:center;color:#6e7681}}
.meta{{padding:8px 10px 2px;font-size:12px;word-break:break-all}}
.meta a{{color:#58a6ff;text-decoration:none}} .title{{padding:0 10px;color:#c9d1d9}}
.counts{{padding:4px 10px 10px;color:#8b949e;font-size:12px}} .counts a{{color:#58a6ff}}
.st{{display:inline-block;padding:0 6px;border-radius:4px;font-weight:600;margin-right:6px}}
.s2{{background:#1a7f37;color:#fff}} .s3{{background:#9e6a03;color:#fff}}
.s4{{background:#8957e5;color:#fff}} .s5{{background:#da3633;color:#fff}}
details{{margin:16px;background:#161b22;border:1px solid #30363d;border-radius:10px;padding:12px}}
code{{color:#ff7b72}} summary{{cursor:pointer;font-weight:600}}
</style></head><body>
<header><h1>Vigía · {out.name}</h1>
<div class="sub">{len(results)} live hosts · {n_endpoints} endpoints · {len(secrets)} potential secrets{intel_str}</div></header>
<details><summary>⚠ Potential secrets ({len(secrets)}) — verify manually, expect false positives</summary>
<ul>{sec_preview}</ul></details>
<div class="grid">{''.join(cards)}</div></body></html>"""
    (out / "index.html").write_text(html)

# ---- main -------------------------------------------------------------------

async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--urls", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--ws", default="ws://obscura:9222")
    ap.add_argument("--handle", default="researcher")
    ap.add_argument("--contact", default="")
    ap.add_argument("--concurrency", type=int, default=5)
    ap.add_argument("--delay-ms", type=int, default=400)
    ap.add_argument("--nav-timeout", type=int, default=25)
    args = ap.parse_args()

    out = Path(args.out)
    urls = [u.strip() for u in Path(args.urls).read_text().splitlines() if u.strip()]
    if not urls:
        print("[!] no urls", file=sys.stderr); return

    results = []
    async with async_playwright() as p:
        browser = await p.chromium.connect_over_cdp(args.ws)
        sem = asyncio.Semaphore(args.concurrency)
        await asyncio.gather(*(crawl_one(browser, u, args, results, sem) for u in urls))
        n_endpoints, secrets = await extract_js(browser, results, args)
        await browser.close()

    print("\n[*] Writing browser intelligence...", flush=True)
    browser_intel = write_browser_intel(results, out)
    build_report(results, out, n_endpoints, secrets, browser_intel)

if __name__ == "__main__":
    asyncio.run(main())
