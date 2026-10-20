#!/usr/bin/env python3
"""
Vigía — crawl + screenshot + JS extraction driver.

Connect to the headless browser over CDP, and for each live URL:
  - screenshot (full page)
  - collect links, <script src>, and every resource URL the page requested
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
                       "links": [], "scripts": [], "resources": [], "error": None}
        ua = f"bugbounty-{args.handle}" + (f" (+{args.contact})" if args.contact else "")
        resources = set()
        try:
            ctx = await browser.new_context(
                user_agent=ua,
                extra_http_headers={"X-Bug-Bounty": args.handle},
                ignore_https_errors=True,
            )
            page = await ctx.new_page()
            page.on("response", lambda r: resources.add(r.url))
            resp = await page.goto(url, wait_until="load", timeout=args.nav_timeout * 1000)
            host_result["status"] = resp.status if resp else None
            host_result["title"] = (await page.title()) or ""

            shot = f"screenshots/{safe_name(url)}.png"
            try:
                await page.screenshot(path=str(Path(args.out) / shot), full_page=True)
                host_result["screenshot"] = shot
            except Exception:
                pass

            anchors = await page.eval_on_selector_all(
                "a[href]", "els => els.map(e => e.href)")
            scripts = await page.eval_on_selector_all(
                "script[src]", "els => els.map(e => e.src)")
            host_result["links"] = sorted(set(anchors))[:2000]
            host_result["scripts"] = sorted(set(scripts))
            host_result["resources"] = sorted(resources)[:3000]

            await ctx.close()
        except Exception as e:
            host_result["error"] = str(e)[:300]

        (Path(args.out) / "crawl" / f"{safe_name(url)}.json").write_text(
            json.dumps(host_result, indent=2))
        results.append(host_result)
        tag = host_result["status"] or host_result["error"] or "?"
        print(f"    [{tag}] {url}", flush=True)
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

# ---- report -----------------------------------------------------------------

def build_report(results, out, n_endpoints, secrets):
    cards = []
    for r in sorted(results, key=lambda x: (x["status"] or 0)):
        shot = (f'<img loading="lazy" src="{r["screenshot"]}">'
                if r["screenshot"] else '<div class="noshot">no screenshot</div>')
        status = r["status"] or r["error"] or "?"
        title = (r["title"] or "").replace("<", "&lt;")[:120]
        cards.append(f"""<div class="card">
  <a href="{r['url']}" target="_blank" rel="noreferrer">{shot}</a>
  <div class="meta"><span class="st s{str(status)[:1]}">{status}</span>
  <a href="{r['url']}" target="_blank" rel="noreferrer">{r['url']}</a></div>
  <div class="title">{title}</div>
  <div class="counts">{len(r['scripts'])} js · {len(r['links'])} links ·
  <a href="crawl/{safe_name(r['url'])}.json">json</a></div>
</div>""")
    sec_preview = "".join(
        f"<li><b>{s['type']}</b>: <code>{s['match'].replace('<','&lt;')}</code></li>"
        for s in secrets[:50]) or "<li>none</li>"
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
<div class="sub">{len(results)} live hosts · {n_endpoints} endpoints · {len(secrets)} potential secrets</div></header>
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

    build_report(results, out, n_endpoints, secrets)

if __name__ == "__main__":
    asyncio.run(main())
