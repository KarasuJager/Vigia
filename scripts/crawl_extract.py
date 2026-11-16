#!/usr/bin/env python3
"""
Vigía — crawl + screenshot + JS extraction driver.

Connect to the headless browser over CDP, and for each live URL:
  - screenshot (full page)
  - collect links, <script src>, and every resource URL the page requested
  - short in-scope crawl (depth/pages budget) inside the SAME browser context
  - record real API calls (XHR/fetch) and cache headers of every response
  - read the app's route/chunk map (Next.js __BUILD_MANIFEST) and fetch the chunks
    the browser never asked for (hidden screens = hidden JS)
  - fetch JS files IN THE SAME CONTEXT (inherits WAF cookies like Akamai)
  - regex out endpoints + likely secrets from downloaded JS
Then build a browsable index.html.

Traffic is identified (User-Agent + X-Bug-Bounty header) and throttled.
No stealth / no evasion — this is authorized bug-bounty recon.
"""
import argparse, asyncio, json, re, sys
from pathlib import Path
from urllib.parse import urlparse, urljoin, urldefrag
import urllib.request

from playwright.async_api import async_playwright


def resolve_cdp_ws(endpoint: str) -> str:
    """If endpoint is http://, query Chrome /json/version for the real WS URL."""
    if not endpoint.startswith("http://"):
        return endpoint
    version_url = endpoint.rstrip("/") + "/json/version"
    try:
        with urllib.request.urlopen(version_url, timeout=5) as resp:
            data = json.loads(resp.read())
        ws_url = data.get("webSocketDebuggerUrl", "")
        if ws_url:
            orig_host = urlparse(endpoint).hostname
            ws_url = ws_url.replace("127.0.0.1", orig_host).replace("localhost", orig_host)
            print(f"    [CDP] Resolved WS: {ws_url}", flush=True)
            return ws_url
    except Exception as e:
        print(f"    [CDP] Could not resolve WS from {version_url}: {e}", flush=True)
    return endpoint

# ---- scope ------------------------------------------------------------------

class Scope:
    """Mismo criterio que recon.sh: include.txt (ERE, lista cerrada) manda; exclude.txt quita;
    sin include, vale cualquier host bajo los roots."""
    def __init__(self, include="", exclude="", roots=""):
        rd = lambda f: [l.strip() for l in Path(f).read_text(errors="replace").splitlines()
                        if l.strip() and not l.lstrip().startswith("#")] if f and Path(f).is_file() else []
        self.inc = [re.compile(p, re.I) for p in rd(include)]
        self.exc = [re.compile(p, re.I) for p in rd(exclude)]
        self.roots = [r.lower().lstrip("*.") for r in rd(roots)]

    def host_ok(self, host: str) -> bool:
        h = (host or "").lower().rstrip(".")
        if not h:
            return False
        if any(p.search(h) for p in self.exc):
            return False
        if self.inc:
            return any(p.search(h) for p in self.inc)
        if self.roots:
            return any(h == r or h.endswith("." + r) for r in self.roots)
        return True

    def url_ok(self, url: str) -> bool:
        try:
            return self.host_ok(urlparse(url).hostname or "")
        except Exception:
            return False

# ---- extraction patterns ----------------------------------------------------

# LinkFinder-style endpoint regex (trimmed).
ENDPOINT_RE = re.compile(r"""
  (?:"|')(
    ((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})      # absolute URL
    | ((?:/|\.\./|\./)[^"'><,;|*()%$^/\\\[\]][^"'><,;|()]{1,})        # relative path
    | ([a-zA-Z0-9_\-/:{}]{1,}/[a-zA-Z0-9_\-/:{}]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[?|/][^"|']{0,}|))   # admite :id y {id}
    | ([a-zA-Z0-9_\-/]{1,}/(?::[a-zA-Z_]+|\{[a-zA-Z_]+\})(?:/[a-zA-Z0-9_\-/:{}]{0,}|))               # accounts/:id , users/{id}/x
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

# Cabeceras que importan para caché/CDN (WCD y cache poisoning)
CACHE_HEADERS = ("cache-control", "age", "expires", "pragma", "vary", "etag", "last-modified",
                 "x-cache", "x-cache-hits", "x-cache-status", "cf-cache-status", "cdn-cache-control",
                 "surrogate-control", "x-served-by", "via", "server", "x-vercel-cache", "x-nextjs-cache",
                 "akamai-cache-status", "x-akamai-cache-status", "x-proxy-cache", "x-drupal-cache",
                 "x-varnish", "x-amz-cf-pop", "x-amz-cf-id", "cf-ray", "x-fastly-request-id",
                 "x-azure-ref", "x-cdn", "x-edge-location", "content-type")

# Enlaces que NUNCA se siguen en el rastreo corto (aunque vayamos sin sesión)
SKIP_LINK_RE = re.compile(r"(log-?out|sign-?out|logoff|delete|remove|destroy|unsubscribe|cancel|"
                          r"revoke|deactivate|/wp-admin|/cdn-cgi/|mailto:|tel:|javascript:)", re.I)
SKIP_EXT_RE = re.compile(r"\.(png|jpe?g|gif|svg|webp|ico|bmp|css|js|map|json|xml|pdf|zip|gz|rar|7z|"
                         r"mp[34]|avi|mov|webm|woff2?|ttf|eot|docx?|xlsx?|pptx?|csv|txt|apk|ipa|exe|dmg)(\?|$)", re.I)

# F4 (16-nov): de qué hosts se puede bajar JS. Sí: in-scope, CDN y terceros conocidos (ficheros estáticos públicos).
# No: otros hosts de la misma empresa que están FUERA de scope (p.ej. secure.<empresa> tras una redirección).
CDN_RE = re.compile(r"(cloudfront\.net|fastly\.net|fastlylb\.net|akamaized\.net|akamaihd\.net|edgekey\.net|edgesuite\.net|"
                    r"azureedge\.net|azurefd\.net|b-cdn\.net|cdn77|stackpathcdn|kxcdn|r2\.dev|"
                    r"googleusercontent\.com|storage\.googleapis\.com|amazonaws\.com)$", re.I)
VENDOR_JS_HOST = re.compile(r"(google|gstatic|doubleclick|facebook|fbcdn|twitter|segment|sentry|datadog|newrelic|nr-data|hotjar|"
                            r"intercom|zendesk|zdassets|stripe|paypal|cdnjs|jsdelivr|unpkg|jquery|youtube|vimeo|linkedin|tiktok|"
                            r"snapchat|sc-static|optimizely|launchdarkly|amplitude|mixpanel|heap|fullstory|contentsquare|onetrust|"
                            r"cookielaw|recaptcha|hcaptcha|polyfill|bootstrapcdn|fontawesome|typekit|adobe|braze|branch\.io|"
                            r"appsflyer|statsig|raygun|transifex|clarity|bing|hubspot|hs-scripts|marketo|pardot|salesforce|"
                            r"cloudflareinsights|cookiebot|trustarc|usercentrics|wistia|vwo|qualtrics|medallia|pendo|walkme|"
                            r"cloudflare\.com)", re.I)


def js_host_ok(u: str, scope) -> bool:
    h = (urlparse(u).hostname or "").lower()
    return bool(h) and (scope.host_ok(h) or bool(CDN_RE.search(h)) or bool(VENDOR_JS_HOST.search(h)))


# Rutas de Next que no son pantallas
NEXT_SKIP = {"/_app", "/_error", "/_document", "/404", "/500", "sortedPages", "__rewrites"}

def safe_name(url: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", url)[:150]

def url_shape(u: str) -> str:
    """Forma de la URL para no visitar /producto/1, /producto/2, ... (una por forma)."""
    p = urlparse(u)
    path = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "{uuid}", p.path, flags=re.I)
    path = re.sub(r"\d+", "{n}", path)
    return f"{p.scheme}://{p.netloc}{path.rstrip('/')}"

# Shared set to avoid fetching the same JS file from multiple crawl contexts
_fetched_js_lock = asyncio.Lock()
_fetched_js = set()

# Lectura del mapa de rutas/chunks dentro de la página (sin peticiones extra)
MANIFEST_JS = """() => {
  const out = {routes: {}, buildId: "", assetPrefix: "", nextData: "", webpackGlobals: [], framework: []};
  try {
    const m = self.__BUILD_MANIFEST;
    if (m) for (const k of Object.keys(m)) if (Array.isArray(m[k])) out.routes[k] = m[k].filter(x => typeof x === "string");
  } catch (e) {}
  try {
    const el = document.getElementById("__NEXT_DATA__");
    if (el) { out.nextData = el.textContent.slice(0, 300000);
              const nd = JSON.parse(el.textContent); out.buildId = nd.buildId || ""; out.assetPrefix = nd.assetPrefix || ""; }
  } catch (e) {}
  try { for (const k of Object.keys(window)) if (/^(webpackChunk|webpackJsonp)/.test(k)) out.webpackGlobals.push(k); } catch (e) {}
  try {
    if (window.__NEXT_DATA__ || self.__next_f) out.framework.push("next");
    if (window.__NUXT__) out.framework.push("nuxt");
    if (window.__remixContext || window.__remixManifest) out.framework.push("remix");
    if (window.ng || document.querySelector("[ng-version]")) out.framework.push("angular");
    if (window.__VUE__ || document.querySelector("[data-v-app]")) out.framework.push("vue");
    if (document.querySelector("[data-reactroot], #__next, #root")) out.framework.push("react?");
  } catch (e) {}
  return out;
}"""

BUILD_MANIFEST_KEY_RE = re.compile(r'"(/[^"]*)"\s*:\s*\[')
BUILD_MANIFEST_CHUNK_RE = re.compile(r'"(static/[^"]+?\.js)"')

# ---- per-host crawl ---------------------------------------------------------

async def crawl_one(browser, url, args, scope, results, sem):
    async with sem:
        host_result = {"url": url, "status": None, "title": "", "screenshot": None,
                       "links": [], "scripts": [], "resources": [], "error": None,
                       "pages": [], "net": [], "manifest": {}, "blocked": False, "out_of_scope_root": None,
                       "out_of_scope_seen": [], "oos_scripts": []}
        ua = args.ua or (f"bugbounty-{args.handle}" + (f" (+{args.contact})" if args.contact else ""))
        resources = set()
        net = []
        oos_tasks = []
        oos_dir = Path(args.out) / "findings" / "js-fuera-de-scope"

        async def keep_oos_js(r):
            # F4 (ver sin tocar): copia del JS que el navegador ya descargó de un host fuera de scope. 0 peticiones extra.
            try:
                body = await r.body()
                if body and len(body) > 20:
                    oos_dir.mkdir(parents=True, exist_ok=True)
                    (oos_dir / (safe_name(r.url) + ".js")).write_bytes(body)
            except Exception:
                pass

        def on_response(r):
            # Registro pasivo de lo que el navegador ya pide: API real + cabeceras de caché
            try:
                if len(net) >= 4000:
                    return
                req = r.request
                hdrs = r.headers or {}
                e = {"url": r.url, "status": r.status, "method": req.method,
                     "type": req.resource_type,
                     "h": {k: hdrs[k][:200] for k in CACHE_HEADERS if k in hdrs},
                     "set_cookie": "set-cookie" in hdrs}
                if req.resource_type in ("xhr", "fetch"):
                    pd = req.post_data
                    if pd:
                        e["body"] = pd[:600]
                net.append(e)
                resources.add(r.url)
                if req.resource_type == "script" and not js_host_ok(r.url, scope) and len(oos_tasks) < 200:
                    oos_tasks.append(asyncio.ensure_future(keep_oos_js(r)))
            except Exception:
                pass

        try:
            ctx = await browser.new_context(
                user_agent=ua,
                extra_http_headers={args.ident_header: args.handle},
                ignore_https_errors=True,
            )
            ctx.on("response", on_response)
            page = await ctx.new_page()
            root_host = (urlparse(url).hostname or "").lower()

            def seen_oos(from_url, final_url, status, depth):
                host_result["out_of_scope_seen"].append({"desde": from_url, "acaba_en": final_url, "status": status, "depth": depth})
                print(f"      ~ {from_url} → {final_url[:100]}  (FUERA DE SCOPE: visto y anotado, no se toca)", flush=True)

            # --- página raíz (las redirecciones se siguen como cualquier visitante) ---
            resp = await page.goto(url, wait_until="load", timeout=args.nav_timeout * 1000)
            root_oos = not scope.url_ok(page.url)              # la raíz acabó fuera de scope (redirección o JS)
            if root_oos:
                host_result["out_of_scope_root"] = page.url
                seen_oos(url, page.url, resp.status if resp else None, 0)
            host_result["status"] = resp.status if resp else None
            host_result["title"] = (await page.title()) or ""
            # si la página final redirige a otro host, el host bueno es el final
            final_host = (urlparse(page.url).hostname or root_host).lower()
            _pu = urlparse(page.url)
            origin = f"{_pu.scheme}://{_pu.netloc}"

            shot = f"screenshots/{safe_name(url)}.png"
            try:
                await page.screenshot(path=str(Path(args.out) / shot), full_page=True)
                host_result["screenshot"] = shot
            except Exception:
                pass

            anchors = await page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
            scripts = await page.eval_on_selector_all("script[src]", "els => els.map(e => e.src)")
            try:
                host_result["manifest"] = await page.evaluate(MANIFEST_JS)
            except Exception:
                host_result["manifest"] = {}
            host_result["pages"].append({"url": page.url, "status": host_result["status"], "depth": 0})
            all_anchors, all_scripts = set(anchors), set(scripts)

            # --- rastreo corto: mismo host, dentro de scope, una URL por "forma" ---
            blocked = host_result["status"] in (401, 403, 429, 503) and args.stop_on_block
            host_result["blocked"] = bool(blocked)
            if args.depth > 0 and args.pages_per_host > 1 and not blocked and not root_oos:
                seen_shapes = {url_shape(page.url), url_shape(url)}
                frontier = [(a, 1) for a in anchors]
                # rutas sin parámetros del mapa de Next: pantallas que existen aunque no haya enlace
                for r in sorted((host_result["manifest"] or {}).get("routes", {}).keys()):
                    if r.startswith("/") and "[" not in r and r not in NEXT_SKIP and not r.startswith("/_"):
                        frontier.append((f"{origin}{r}", 1))
                visited = 1
                consecutive_blocks = 0
                while frontier and visited < args.pages_per_host:
                    link, d = frontier.pop(0)
                    link = urldefrag(link)[0]
                    p = urlparse(link)
                    if p.scheme not in ("http", "https") or (p.hostname or "").lower() != final_host:
                        continue
                    if not scope.url_ok(link) or SKIP_LINK_RE.search(link) or SKIP_EXT_RE.search(p.path):
                        continue
                    shp = url_shape(link)
                    if shp in seen_shapes:
                        continue
                    seen_shapes.add(shp)
                    await asyncio.sleep(args.delay_ms / 1000)
                    try:
                        r2 = await page.goto(link, wait_until="load", timeout=args.nav_timeout * 1000)
                        st = r2.status if r2 else None
                    except Exception as e:
                        host_result["pages"].append({"url": link, "status": None, "depth": d, "error": str(e)[:120]})
                        continue
                    visited += 1
                    if not scope.url_ok(page.url):
                        seen_oos(link, page.url, st, d)            # visto y anotado; no se siguen sus enlaces
                        continue
                    host_result["pages"].append({"url": page.url, "status": st, "depth": d})
                    print(f"      · [{st}] {link}", flush=True)
                    if st in (403, 429, 503):
                        consecutive_blocks += 1
                        if args.stop_on_block and consecutive_blocks >= 3:
                            print("      ! 3 bloqueos seguidos: paro el rastreo de este host", flush=True)
                            host_result["blocked"] = True
                            break
                        continue
                    consecutive_blocks = 0
                    try:
                        a2 = await page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
                        s2 = await page.eval_on_selector_all("script[src]", "els => els.map(e => e.src)")
                    except Exception:
                        a2, s2 = [], []
                    all_anchors.update(a2)
                    all_scripts.update(s2)
                    if d + 1 <= args.depth:
                        frontier.extend((a, d + 1) for a in a2)

            host_result["links"] = sorted(all_anchors)[:3000]
            if root_oos:
                host_result["oos_scripts"] = sorted(all_scripts)
                all_scripts = set()
                resources = {u for u in resources if scope.url_ok(u)}
            host_result["scripts"] = sorted(all_scripts)
            host_result["resources"] = sorted(resources)[:4000]

            # --- JS a descargar: lo que cargó el navegador + chunks del mapa de Next ---
            js_urls_here = set()
            for u in host_result["scripts"] + list(resources):
                if u.split("?")[0].lower().endswith((".js", ".mjs")):
                    js_urls_here.add(u)
            chunk_urls = set()
            bm = next((u for u in resources if "/_buildManifest.js" in u), "")
            man = host_result["manifest"] or {}
            base = ""
            if bm:
                base = bm.split("/static/")[0] + "/"            # https://x/_next/  (respeta assetPrefix/CDN)
            elif man.get("buildId"):
                ap = man.get("assetPrefix") or ""
                base = (ap.rstrip("/") + "/_next/") if ap.startswith("http") else f"{origin}{ap}/_next/"
            if base:
                for r, chunks in (man.get("routes") or {}).items():
                    for c in chunks:
                        if c.endswith(".js"):
                            chunk_urls.add(urljoin(base, c))
                host_result["manifest"]["chunk_base"] = base

            js_raw_dir = Path(args.out) / "findings" / "js-raw"
            js_raw_dir.mkdir(parents=True, exist_ok=True)

            skipped_oos = 0

            async def fetch_js(js_url) -> str:
                nonlocal skipped_oos
                if not js_host_ok(js_url, scope):               # F4: JS de un host de la empresa fuera de scope
                    skipped_oos += 1
                    return ""
                async with _fetched_js_lock:
                    if js_url in _fetched_js:
                        return ""
                    _fetched_js.add(js_url)
                try:
                    js_resp = await ctx.request.get(js_url, timeout=args.nav_timeout * 1000)
                    if js_resp.status in (403, 429, 503):
                        return ""
                    body = await js_resp.text()
                    if body and len(body.strip()) > 20 and not body.lstrip()[:15].lower().startswith(("<!doctype", "<html")):
                        (js_raw_dir / (safe_name(js_url) + ".js")).write_text(body, errors="replace")
                        return body
                except Exception:
                    pass
                finally:
                    await asyncio.sleep(args.delay_ms / 1000)
                return ""

            fetched_count = 0
            bm_body = ""
            for js_url in sorted(js_urls_here):
                b = await fetch_js(js_url)
                if b:
                    fetched_count += 1
                    if "/_buildManifest.js" in js_url:
                        bm_body = b
            # Si la página no expuso __BUILD_MANIFEST, se lee del fichero descargado
            if bm_body and not man.get("routes"):
                routes = sorted(set(BUILD_MANIFEST_KEY_RE.findall(bm_body)))
                host_result["manifest"]["routes"] = {r: [] for r in routes}
                for c in BUILD_MANIFEST_CHUNK_RE.findall(bm_body):
                    chunk_urls.add(urljoin(bm.split("/static/")[0] + "/", c))
            # Manifiesto de middleware (rutas protegidas por middleware en Next): 1 petición
            if bm:
                mm = bm.replace("_buildManifest.js", "_middlewareManifest.js")
                b = await fetch_js(mm)
                if b:
                    host_result["manifest"]["middleware"] = sorted(set(re.findall(r'"(/[^"]{1,200})"', b)))[:200]
            hidden_chunks = sorted(chunk_urls - js_urls_here)[: args.chunks_max]
            got_hidden = 0
            for cu in hidden_chunks:
                if await fetch_js(cu):
                    got_hidden += 1
            host_result["manifest"]["hidden_chunks"] = got_hidden
            if skipped_oos:
                host_result["js_skipped_out_of_scope"] = skipped_oos
                print(f"      -> {skipped_oos} JS no bajados: su host está fuera de scope", flush=True)
            if fetched_count or got_hidden:
                print(f"      -> {fetched_count} JS files saved (in-context)"
                      + (f" + {got_hidden} chunks ocultos del mapa de rutas" if got_hidden else ""), flush=True)

            if oos_tasks:
                await asyncio.gather(*oos_tasks, return_exceptions=True)
                n_oos = len(list(oos_dir.glob("*.js"))) if oos_dir.exists() else 0
                print(f"      -> JS de hosts fuera de scope guardado SIN pedirlo otra vez (lo trajo el navegador): {n_oos} en js-fuera-de-scope/", flush=True)
            await ctx.close()
        except Exception as e:
            host_result["error"] = str(e)[:300]

        host_result["net"] = net
        (Path(args.out) / "crawl" / f"{safe_name(url)}.json").write_text(
            json.dumps(host_result, indent=2))
        results.append(host_result)
        tag = host_result["status"] or host_result["error"] or "?"
        print(f"    [{tag}] {url}  ({len(host_result['pages'])} páginas)", flush=True)
        await asyncio.sleep(args.delay_ms / 1000)

# ---- API real + mapa de caché + rutas ----------------------------------------

def _norm_api(u: str) -> str:
    p = urlparse(u)
    q = "&".join(sorted(set(kv.split("=")[0] + "=" for kv in p.query.split("&") if kv))) if p.query else ""
    return f"{p.scheme}://{p.netloc}{p.path}" + (f"?{q}" if q else "")

def _cache_class(e: dict) -> str:
    t = e.get("type", "")
    ct = (e.get("h", {}).get("content-type") or "").lower()
    path = urlparse(e["url"]).path.lower()
    if t == "document" or "text/html" in ct:
        return "html"
    if t in ("xhr", "fetch") or "json" in ct:
        return "api"
    if re.search(r"\.(js|mjs|css)$", path) or t in ("script", "stylesheet"):
        return "static"
    if t in ("image", "font", "media"):
        return "media"
    return "other"

def _hit(h: dict) -> str:
    for k in ("cf-cache-status", "x-cache", "x-cache-status", "x-vercel-cache", "x-nextjs-cache",
              "akamai-cache-status", "x-akamai-cache-status", "x-proxy-cache", "x-drupal-cache"):
        v = (h.get(k) or "").upper()
        if not v:
            continue
        if "HIT" in v or v in ("STALE", "REVALIDATED", "UPDATING"):
            return "HIT"
        if "MISS" in v or "EXPIRED" in v:
            return "MISS"
        if "DYNAMIC" in v or "BYPASS" in v or "PASS" in v:
            return "BYPASS"
    try:
        if int(h.get("age", "0") or 0) > 0:
            return "HIT"
    except Exception:
        pass
    return ""

def _cdn(h: dict) -> str:
    s = " ".join(f"{k}:{v}" for k, v in h.items()).lower()
    for name, needle in (("cloudflare", "cf-ray"), ("cloudflare", "cloudflare"), ("cloudfront", "x-amz-cf"),
                         ("cloudfront", "cloudfront"), ("akamai", "akamai"), ("fastly", "fastly"),
                         ("fastly", "x-served-by:cache-"), ("vercel", "x-vercel"), ("azure-fd", "x-azure-ref"),
                         ("varnish", "varnish"), ("google", "gws"), ("netlify", "netlify")):
        if needle in s:
            return name
    return ""

def _cacheable_cc(cc: str) -> bool:
    cc = (cc or "").lower()
    if not cc or "no-store" in cc or "private" in cc or "no-cache" in cc:
        return False
    m = re.search(r"(?:s-maxage|max-age)=(\d+)", cc)
    return bool(m and int(m.group(1)) > 0) or "public" in cc

def write_net_outputs(results, out: Path, scope: Scope):
    fd = out / "findings"
    fd.mkdir(parents=True, exist_ok=True)
    # 1) llamadas API reales (XHR/fetch)
    api, third = {}, 0
    for r in results:
        for e in r.get("net", []):
            if e.get("type") not in ("xhr", "fetch"):
                continue
            if not scope.url_ok(e["url"]):
                third += 1
                continue
            key = (e["method"], _norm_api(e["url"]))
            if key in api:
                continue
            gql = ""
            b = e.get("body") or ""
            m = re.search(r'"operationName"\s*:\s*"([A-Za-z_]\w*)"', b) or re.search(r"(query|mutation)\s+([A-Za-z_]\w*)", b)
            if m:
                gql = m.group(m.lastindex)
            api[key] = {"method": e["method"], "url": e["url"], "status": e["status"],
                        "content_type": (e.get("h", {}).get("content-type") or "")[:60],
                        "graphql_op": gql, "body_sample": b[:300], "from_page": r["url"]}
    rows = sorted(api.values(), key=lambda x: (x["url"], x["method"]))
    (fd / "api-calls.jsonl").write_text("\n".join(json.dumps(x, ensure_ascii=False) for x in rows))
    (fd / "api-calls.txt").write_text("\n".join(
        f"{x['method']:6} {x['status']}  {x['url']}" + (f"   [GraphQL: {x['graphql_op']}]" if x["graphql_op"] else "")
        for x in rows))
    # 2) mapa de caché por host (solo in-scope)
    hosts = {}
    for r in results:
        for e in r.get("net", []):
            if not scope.url_ok(e["url"]):
                continue
            h = urlparse(e["url"]).hostname or ""
            st = hosts.setdefault(h, {"cdn": set(), "vary": set(), "classes": {}, "cf_bypass": 0})
            c = _cache_class(e)
            hd = e.get("h", {})
            cdn = _cdn(hd)
            if cdn:
                st["cdn"].add(cdn)
            if hd.get("vary"):
                st["vary"].add(hd["vary"][:80])
            if (hd.get("cf-cache-status") or "").upper() == "BYPASS":   # Cloudflare: BYPASS (≠ DYNAMIC) = regla de caché a mano
                st["cf_bypass"] += 1
            cl = st["classes"].setdefault(c, {"n": 0, "hit": 0, "cacheable": 0, "cc": {}, "set_cookie_cached": 0,
                                               "samples": []})
            cl["n"] += 1
            hit = _hit(hd)
            cc = hd.get("cache-control") or ""
            if hit == "HIT":
                cl["hit"] += 1
            if _cacheable_cc(cc) or hit == "HIT":
                cl["cacheable"] += 1
                if e.get("set_cookie"):
                    cl["set_cookie_cached"] += 1
            if cc:
                cl["cc"][cc[:70]] = cl["cc"].get(cc[:70], 0) + 1
            if len(cl["samples"]) < 3:
                cl["samples"].append(e["url"][:160])
    lines, js = [], {}
    for h in sorted(hosts):
        st = hosts[h]
        cls = st["classes"]
        stat = cls.get("static", {})
        html = cls.get("html", {})
        apic = cls.get("api", {})
        static_cached = stat.get("cacheable", 0) > 0
        dyn_n = html.get("n", 0) + apic.get("n", 0)
        dyn_cached = html.get("cacheable", 0) + apic.get("cacheable", 0)
        # F9 (16-nov): la señal exige CACHÉ OBSERVADA, no solo un CDN delante (un target salía MEDIA sin ver nada cacheado).
        # El ataque WCD busca que una ruta dinámica "parezca" estática y se cachee con datos de la víctima.
        shared = stat.get("hit", 0) > 0 or (bool(st["cdn"]) and static_cached)   # caché compartida, no solo la del navegador
        if shared and dyn_n and dyn_cached == 0:
            sig = "ALTA (caché compartida en estáticos + páginas/API dinámicas sin caché)"
        elif st["cf_bypass"]:
            sig = f"MEDIA (Cloudflare responde BYPASS en {st['cf_bypass']} respuestas: hay una regla de caché a mano)"
        elif static_cached and not dyn_n:
            sig = "MEDIA (estáticos cacheados, pero no se vieron páginas/API dinámicas sin sesión)"
        elif static_cached:
            sig = "MEDIA (estáticos cacheables solo por cabeceras, sin HIT ni CDN que lo confirme)"
        else:
            sig = "BAJA (" + ("solo CDN delante, sin caché observada" if st["cdn"] else "sin caché observada") + ")"
        if dyn_cached:
            sig += " · OJO: HTML/API cacheable (mirar cache poisoning)"
        def fmt(name, c):
            if not c:
                return f"{name}: —"
            top = max(c["cc"].items(), key=lambda kv: kv[1])[0] if c["cc"] else "sin Cache-Control"
            return f"{name}: {c['n']} resp · {c['hit']} HIT · {c['cacheable']} cacheables · '{top}'"
        lines.append(f"{h}\n  CDN: {', '.join(sorted(st['cdn'])) or 'no visto'} · señal WCD: {sig}\n"
                     f"  {fmt('estáticos', stat)}\n  {fmt('HTML', html)}\n  {fmt('API', apic)}\n"
                     f"  Vary: {' | '.join(sorted(st['vary'])[:3]) or '—'}\n")
        js[h] = {"cdn": sorted(st["cdn"]), "wcd_signal": sig, "vary": sorted(st["vary"]),
                 "classes": {k: {kk: vv for kk, vv in v.items()} for k, v in cls.items()}}
    (fd / "cache-map.txt").write_text(
        "# Mapa de caché (pasivo, del tráfico normal del crawl). Señal WCD = dónde merece la pena probar a mano.\n"
        "# ALTA: caché compartida observada en estáticos + HTML/API sin caché. MEDIA: indicios incompletos o regla de\n"
        "# Cloudflare (BYPASS). BAJA: sin caché observada (un CDN delante no basta). No es un hallazgo: es dónde mirar.\n\n" + "\n".join(lines))
    (fd / "cache-map.json").write_text(json.dumps(js, indent=1))
    # 3) rutas y chunks del mapa de la app
    routes, mw, hidden = set(), set(), 0
    for r in results:
        m = r.get("manifest") or {}
        h = urlparse(r["url"]).netloc
        bid = m.get("buildId", "")
        for k in (m.get("routes") or {}):
            if k.startswith("/") and k not in NEXT_SKIP:
                routes.add(f"{h}{k}")
                if bid and "[" not in k and not k.startswith("/_"):
                    routes.add(f"{h}/_next/data/{bid}{'/index' if k == '/' else k}.json   (datos de la página)")
        for k in m.get("middleware") or []:
            mw.add(f"{h} {k}")
        hidden += m.get("hidden_chunks", 0) or 0
    (fd / "app-routes.txt").write_text("\n".join(sorted(routes)))
    oos = [(r["url"], x) for r in results for x in (r.get("out_of_scope_seen") or [])]
    if oos:
        (fd / "fuera-de-scope.txt").write_text(
            "# VISTO — FUERA DE SCOPE — NO TOCAR. Lo enseñó la propia web (redirecciones). Contexto, no objetivo.\n"
            "# Si la cadena vuelve a scope (p.ej. un login central), la parte en scope sí se trabaja.\n\n" +
            "\n".join(f"{x['desde']}  →  {x['acaba_en']}  (estado {x['status']}, profundidad {x['depth']})" for _, x in oos))
    if mw:
        (fd / "middleware-routes.txt").write_text("\n".join(sorted(mw)))
    print(f"    -> API real: {len(rows)} llamadas in-scope ({third} de terceros ignoradas) · "
          f"caché: {len(hosts)} hosts ({sum(1 for v in js.values() if v['wcd_signal'].startswith('ALTA'))} con señal WCD ALTA) · "
          f"rutas de la app: {len(routes)} · chunks ocultos: {hidden}", flush=True)
    return len(rows), js, len(routes)

# ---- JS endpoint / secret extraction (from disk) ---------------------------

def extract_js_from_disk(args):
    """Analyse JS files already saved to disk by crawl_one (no network needed)."""
    js_raw_dir = Path(args.out) / "findings" / "js-raw"
    if not js_raw_dir.exists():
        print("[*] No JS files downloaded — skipping extraction", flush=True)
        return 0, []

    js_files = sorted(js_raw_dir.glob("*.js"))
    print(f"[*] Extracting from {len(js_files)} JS files", flush=True)

    endpoints, secrets = {}, []
    for js_file in js_files:
        try:
            body = js_file.read_text(errors="replace")
        except Exception:
            continue
        source = js_file.name  # filename
        for m in ENDPOINT_RE.finditer(body):
            ep = m.group(1).strip("\"'")
            if 1 < len(ep) < 250:
                endpoints.setdefault(ep, set()).add(source)
        for label, pat in SECRET_PATTERNS:
            for sm in pat.finditer(body):
                secrets.append({
                    "type": label,
                    "match": sm.group(0)[:120],
                    "source": source,
                })

    ep_lines = [f"{ep}\t<- {sorted(srcs)[0]}"
                for ep, srcs in sorted(endpoints.items())]
    (Path(args.out) / "findings" / "endpoints.txt").write_text(
        "\n".join(ep_lines))
    sec_lines = [f"[{s['type']}] {s['match']}  ({s['source']})"
                 for s in secrets]
    (Path(args.out) / "findings" / "secrets.txt").write_text(
        "\n".join(sec_lines))
    print(f"    -> {len(endpoints)} endpoints, {len(secrets)} potential secrets",
          flush=True)
    return len(endpoints), secrets

# ---- report -----------------------------------------------------------------

def build_report(results, out, n_endpoints, secrets, n_api=0, cache=None, n_routes=0):
    cache = cache or {}
    cards = []
    for r in sorted(results, key=lambda x: (x["status"] or 0)):
        shot = (f'<img loading="lazy" src="{r["screenshot"]}">'
                if r["screenshot"] else '<div class="noshot">no screenshot</div>')
        status = r["status"] or r["error"] or "?"
        title = (r["title"] or "").replace("<", "&lt;")[:120]
        h = urlparse(r["url"]).hostname or ""
        wcd = (cache.get(h) or {}).get("wcd_signal", "")
        cards.append(f"""<div class="card">
  <a href="{r['url']}" target="_blank" rel="noreferrer">{shot}</a>
  <div class="meta"><span class="st s{str(status)[:1]}">{status}</span>
  <a href="{r['url']}" target="_blank" rel="noreferrer">{r['url']}</a></div>
  <div class="title">{title}</div>
  <div class="counts">{len(r['scripts'])} js · {len(r.get('pages', []))} páginas · {len(r['links'])} links ·
  {('WCD ' + wcd.split(' ')[0] + ' · ') if wcd else ''}<a href="crawl/{safe_name(r['url'])}.json">json</a></div>
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
.sub a{{color:#58a6ff}}
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
<div class="sub">{len(results)} live hosts · {n_endpoints} endpoints · {len(secrets)} potential secrets ·
{n_api} llamadas API reales · {n_routes} rutas de la app ·
<a href="findings/cache-map.txt">mapa de caché</a> · <a href="findings/api-calls.txt">API</a> ·
<a href="findings/app-routes.txt">rutas</a> · <a href="findings/hidden/RESUMEN.md">escondido</a> ·
<a href="findings/endpoints-top.txt">endpoints top</a></div></header>
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
    ap.add_argument("--ua", default="", help="User-Agent completo (si el programa exige uno exacto)")
    ap.add_argument("--ident-header", default="X-Bug-Bounty", help="nombre de la cabecera de identificación (p.ej. X-HackerOne-Research)")
    ap.add_argument("--contact", default="")
    ap.add_argument("--concurrency", type=int, default=5)
    ap.add_argument("--delay-ms", type=int, default=400)
    ap.add_argument("--nav-timeout", type=int, default=25)
    ap.add_argument("--include", default="", help="ERE de hosts in-scope (scope/<p>.include.txt)")
    ap.add_argument("--exclude", default="", help="ERE de hosts fuera de scope (scope/<p>.exclude.txt)")
    ap.add_argument("--roots", default="", help="roots.txt del run (si no hay include)")
    ap.add_argument("--depth", type=int, default=2, help="profundidad del rastreo corto (0 = solo la portada)")
    ap.add_argument("--pages-per-host", type=int, default=10, help="máximo de páginas por host")
    ap.add_argument("--chunks-max", type=int, default=300, help="máximo de chunks ocultos a bajar por host")
    ap.add_argument("--no-stop-on-block", dest="stop_on_block", action="store_false")
    ap.add_argument("--extract-only", action="store_true",
                    help="no navega: solo re-extrae endpoints/secrets de findings/js-raw (p.ej. tras los source maps)")
    args = ap.parse_args()

    out = Path(args.out)
    if args.extract_only:
        n_endpoints, secrets = extract_js_from_disk(args)
        print(f"    -> {n_endpoints} endpoints, {len(secrets)} potential secrets (re-extracción sobre js-raw)")
        return
    urls = [u.strip() for u in Path(args.urls).read_text().splitlines() if u.strip()]
    if not urls:
        print("[!] no urls", file=sys.stderr); return
    scope = Scope(args.include, args.exclude, args.roots)
    print(f"[*] Rastreo corto: profundidad {args.depth}, máx. {args.pages_per_host} páginas/host, "
          f"{args.delay_ms} ms entre peticiones", flush=True)

    results = []
    async with async_playwright() as p:
        ws_endpoint = resolve_cdp_ws(args.ws)
        browser = await p.chromium.connect_over_cdp(ws_endpoint)
        sem = asyncio.Semaphore(args.concurrency)
        await asyncio.gather(*(crawl_one(browser, u, args, scope, results, sem) for u in urls))
        await browser.close()

    n_api, cache, n_routes = write_net_outputs(results, out, scope)

    # JS analysis runs on files already saved to disk (no browser needed)
    n_endpoints, secrets = extract_js_from_disk(args)

    build_report(results, out, n_endpoints, secrets, n_api, cache, n_routes)

if __name__ == "__main__":
    asyncio.run(main())
