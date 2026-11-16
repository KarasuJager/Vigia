#!/usr/bin/env python3
"""
Vigía — lo escondido en el JS (sin tráfico: solo lee lo que ya está en findings/js-raw).

Saca lo que las herramientas genéricas no buscan y es donde suele estar el bounty:
  - flags.txt        feature flags (funciones que existen pero están apagadas)
  - roles.txt        roles y permisos comprobados en el cliente
  - graphql-ops.txt  queries / mutations / subscriptions con nombre (y hashes de persisted queries)
  - routes.txt       rutas del router del front (React/Vue/Angular) + rutas de la app de Next (app-routes)
  - config.txt       configuración embebida (NEXT_PUBLIC_*, REACT_APP_*, VITE_*, apiUrl/baseURL, __NEXT_DATA__)
  - hosts.txt        hosts que aparecen en el JS: in-scope / misma organización (NO se tocan) / terceros
  - RESUMEN.md       lo más jugoso de todo lo anterior, para Manu y los agentes

Además genera findings/endpoints-top.txt: los endpoints ordenados por interés
(in-scope, con IDs, API/GraphQL, parámetros de redirección/fichero, admin/interno) para que
los agentes no se coman miles de líneas.

Uso:  python3 js_hidden.py <run-dir> [--include scope.include.txt] [--exclude scope.exclude.txt] [--roots roots.txt]
"""
import argparse, json, re, sys
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent))
try:
    from crawl_extract import Scope
except Exception:                       # sin playwright instalado (pruebas): scope mínimo
    class Scope:
        def __init__(self, include="", exclude="", roots=""):
            rd = lambda f: [l.strip() for l in Path(f).read_text().splitlines() if l.strip() and not l.startswith("#")] if f and Path(f).is_file() else []
            self.inc = [re.compile(p, re.I) for p in rd(include)]
            self.exc = [re.compile(p, re.I) for p in rd(exclude)]
            self.roots = [r.lower() for r in rd(roots)]
        def host_ok(self, h):
            h = (h or "").lower()
            if any(p.search(h) for p in self.exc): return False
            if self.inc: return any(p.search(h) for p in self.inc)
            return any(h == r or h.endswith("." + r) for r in self.roots) if self.roots else True

# ---- patrones ---------------------------------------------------------------

FLAG_RES = [
    re.compile(r"""(?:variation|boolVariation|stringVariation|isFeatureEnabled|isEnabled|useFlag|useFeature|useFeatureFlag|getFeatureValue|isOn|getTreatment|getFlag|checkGate|featureEnabled|hasFeature)\s*\(\s*["'`]([A-Za-z0-9_.:\-]{3,80})["'`]"""),
    re.compile(r"""(?:featureFlags?|features|flags|toggles)\s*[.\[]\s*["']?([A-Za-z_][A-Za-z0-9_\-]{2,60})"""),
    re.compile(r"""["']((?:ff|feature|enable|enabled|disable|beta|experiment|exp|flag)[_.][A-Za-z0-9_\-.]{2,60})["']""", re.I),
]
FLAG_OBJ_RE = re.compile(r"""(?:featureFlags?|flags|features|toggles)\s*[:=]\s*\{([^{}]{3,1500})\}""")
FLAG_KEY_RE = re.compile(r"""["']?([A-Za-z_][A-Za-z0-9_\-]{2,60})["']?\s*:\s*(?:!0|!1|true|false)""")
FLAG_SDK_RE = re.compile(r"(launchdarkly|ldclient|growthbook|split\.io|splitio|unleash|optimizely|flagsmith|configcat|statsig|posthog\.isFeatureEnabled)", re.I)

ROLE_RES = [
    re.compile(r"""(?:role|roles|userRole|user_role|accountType|account_type|userType|user_type|memberType|tier|plan)\s*(?:===?|!==?)\s*["'`]([A-Za-z0-9_:\-]{2,40})["'`]""", re.I),
    re.compile(r"""(?:roles?|permissions?|scopes?|grants?)\s*\.\s*(?:includes|indexOf|has|some)\s*\(\s*["'`]([A-Za-z0-9_:.\-]{2,60})["'`]""", re.I),
    re.compile(r"""(?:hasPermission|hasRole|hasScope|can|cannot|isAllowed|authorize|checkPermission|requirePermission|hasAccess|userCan)\s*\(\s*["'`]([A-Za-z0-9_:.\-]{2,60})["'`](?:\s*,\s*["'`]([A-Za-z0-9_:.\-]{2,60})["'`])?"""),
    re.compile(r"""["'`]((?:ROLE|PERM|PERMISSION|SCOPE)_[A-Z0-9_]{2,50})["'`]"""),
    re.compile(r"""["'`]([a-z][a-z0-9_\-]{2,30}:(?:read|write|create|update|delete|manage|admin|view|edit|export|refund|approve)[a-z_]*)["'`]"""),
]
ROLE_FLAG_RE = re.compile(r"\b(is(?:Admin|SuperAdmin|Superuser|Staff|Internal|Employee|Owner|Manager|Support|Moderator|Root|God|Impersonating))\b")

# URLs en plantillas `...${id}...` (el regex de endpoints clásico solo mira comillas simples/dobles)
TEMPLATE_URL_RE = re.compile(r"""`((?:https?://[^`\s]{3,200}|/[A-Za-z0-9_\-]+/[^`\s]{1,200})\$\{[^`]{0,200})`""")
GQL_RE = re.compile(r"""\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]{2,80})\s*[({]""")
GQL_HASH_RE = re.compile(r"""["']?sha256Hash["']?\s*:\s*["']([a-f0-9]{64})["']""")
GQL_OPNAME_RE = re.compile(r"""["']?operationName["']?\s*:\s*["']([A-Za-z_][A-Za-z0-9_]{2,80})["']""")

ROUTE_RES = [
    re.compile(r"""\bpath\s*:\s*["'`](/?[A-Za-z0-9_\-/:.*?()\[\]{}]{1,120})["'`]"""),            # React Router objects / Vue / Angular
    re.compile(r"""<Route[^>]{0,200}\bpath\s*=\s*\{?["'`](/[^"'`]{0,120})["'`]"""),
    re.compile(r"""(?:navigate|push|replace|redirect|router\.push|history\.push|Navigate\s+to=)\s*\(?\s*["'`](/[A-Za-z0-9_\-/:.]{1,120})["'`]"""),
]

CONFIG_RES = [
    re.compile(r"""["']?((?:NEXT_PUBLIC|REACT_APP|VITE|VUE_APP|NUXT_PUBLIC|GATSBY|EXPO_PUBLIC)_[A-Z0-9_]{2,60})["']?\s*:\s*["'`]([^"'`]{1,200})["'`]"""),
    re.compile(r"""["']?(api(?:Url|URL|Base|BaseUrl|Endpoint|Host|Root|_url|_base)|baseURL|baseUrl|backendUrl|graphqlUrl|graphqlEndpoint|wsUrl|socketUrl|cdnUrl|authUrl|authDomain|issuer|clientId|client_id|tenantId|environment|env|stage)["']?\s*[:=]\s*["'`]([^"'`\s]{2,200})["'`]"""),
]

HOST_RE = re.compile(r"""(?:https?:)?//([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+)(?::\d+)?""", re.I)
INTERNAL_HINT = re.compile(r"(^|[.\-])(dev|develop|staging|stage|stg|qa|uat|test|internal|intranet|corp|admin|preprod|pre|sandbox|beta|canary|local|private|vpn|jenkins|grafana|kibana)([.\-]|\d|$)", re.I)
THIRD_PARTY = re.compile(r"(google|gstatic|googleapis|doubleclick|facebook|fbcdn|twitter|segment|sentry|datadog|newrelic|hotjar|"
                         r"intercom|zendesk|stripe|paypal|cloudflare|cloudfront|akamai|fastly|jsdelivr|unpkg|cdnjs|w3\.org|"
                         r"schema\.org|github|gitlab|mozilla|apple|microsoft|amazonaws|azure|youtube|vimeo|linkedin|tiktok|"
                         r"optimizely|launchdarkly|amplitude|mixpanel|fullstory|onetrust|cookielaw|recaptcha|hcaptcha|"
                         r"polyfill|bootstrapcdn|fontawesome|typekit|adobe|braze|branch\.io|appsflyer|split\.io|statsig)", re.I)

# endpoints-top
ID_SEG = re.compile(r"(/\d{1,19}(?=/|$|\?)|/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|/:[A-Za-z_]+|/\{[A-Za-z_]+\}|/\$\{[^}]+\}|\[id\]|\[[a-zA-Z]+\]|\{v\})", re.I)
API_HINT = re.compile(r"(/api/|/v\d+/|/graphql|/rest/|/rpc/|/gql|/query|/_next/data/|/ajax/|/services?/)", re.I)
INTERESTING_PARAM = re.compile(r"[?&](redirect|redirect_uri|return|returnUrl|return_to|next|url|uri|dest|destination|callback|continue|goto|target|file|path|template|page|view|include|doc|download|export|format|id|user_?id|account_?id|order_?id|org_?id|tenant)=", re.I)
SENSITIVE = re.compile(r"(admin|internal|debug|staff|impersonat|export|import|billing|payout|refund|invoice|payment|transfer|wallet|token|secret|apikey|api-key|webhook|role|permission|invite|member|tenant|org|account|user|order|upload|backup|config|setting|graphql|private|audit)", re.I)
NOISE = re.compile(r"(\.(png|jpe?g|gif|svg|webp|ico|css|woff2?|ttf|eot|map|mp4|mp3|webm)(\?|$)|/static/media/|/locales?/|/i18n/|node_modules|sourceMappingURL|^data:|w3\.org|schema\.org)", re.I)


FILE_HOST_RE = re.compile(r"^(?:gf_)?https?___([A-Za-z0-9.\-]+)")
LIB_FILE_RE = re.compile(r"(node_modules|webpack_bootstrap|webpack_runtime|\(webpack\)|polyfill|vendor[s]?[._~-]|framework[.-]|core-js|regenerator)", re.I)


# F1 (16-nov): el target sirve SU código desde un CDN (vendappcdn.*.fastly.net, d…cloudfront.net): no es tercero
CDN_RE = re.compile(r"(cloudfront\.net|fastly\.net|fastlylb\.net|akamaized\.net|akamaihd\.net|edgekey\.net|edgesuite\.net|"
                    r"azureedge\.net|azurefd\.net|b-cdn\.net|cdn77|stackpathcdn|kxcdn|r2\.dev|"
                    r"googleusercontent\.com|storage\.googleapis\.com|amazonaws\.com)$", re.I)
# Terceros que también sirven desde CDN (no confundir con el CDN del target). Misma lista que el explorador de Atalaya.
VENDOR_JS_HOST = re.compile(r"(google|gstatic|doubleclick|facebook|fbcdn|twitter|segment|sentry|datadog|newrelic|nr-data|hotjar|"
                            r"intercom|zendesk|zdassets|stripe|paypal|cdnjs|jsdelivr|unpkg|jquery|youtube|vimeo|linkedin|tiktok|"
                            r"snapchat|sc-static|optimizely|launchdarkly|amplitude|mixpanel|heap|fullstory|contentsquare|onetrust|"
                            r"cookielaw|recaptcha|hcaptcha|polyfill|bootstrapcdn|fontawesome|typekit|adobe|braze|branch\.io|"
                            r"appsflyer|statsig|raygun|transifex|clarity|bing|hubspot|hs-scripts|marketo|pardot|salesforce|"
                            r"cloudflareinsights|cookiebot|trustarc|usercentrics|wistia|vwo|qualtrics|medallia|pendo|walkme)", re.I)


def first_party_cdn_hosts(out: Path, scope) -> set:
    """Hosts de CDN que sirven JS a páginas IN-SCOPE del crawl y no son terceros conocidos → código del target."""
    hosts = set()
    for cf in (out / "crawl").glob("*.json") if (out / "crawl").exists() else []:
        try:
            j = json.loads(read(cf))
        except Exception:
            continue
        if not scope.host_ok(urlparse(j.get("url", "")).hostname or ""):
            continue
        for u in (j.get("scripts") or []) + (j.get("resources") or []):
            h = (urlparse(u).hostname or "").lower()
            if h and u.split("?")[0].endswith((".js", ".mjs")) and CDN_RE.search(h) and not VENDOR_JS_HOST.search(h):
                hosts.add(h)
    return hosts


def file_is_target(name: str, scope, cdn=frozenset()) -> bool:
    """¿El fichero JS es código del target (in-scope o de su CDN, y no librería)? Los de terceros y las librerías
    solo meten ruido en flags/roles/rutas."""
    if LIB_FILE_RE.search(name) or "transifex" in name.lower():
        return False
    m = FILE_HOST_RE.match(name)
    if m:
        return scope.host_ok(m.group(1)) or m.group(1).lower() in cdn
    return True                                  # smap_<ruta del fuente> y otros: código propio


JS_WORDS = {"forEach", "includes", "map", "filter", "length", "push", "indexOf", "some", "every", "find", "keys",
            "values", "entries", "reduce", "has", "get", "set", "concat", "join", "slice", "splice", "sort", "default",
            "prototype", "constructor", "call", "apply", "bind", "then", "toString", "value", "enabled", "disabled",
            "add", "delete", "clear", "size", "name", "type", "id", "key", "data", "options", "config"}


def read(f: Path) -> str:
    try:
        return f.read_text(errors="replace")
    except Exception:
        return ""


def main():
    ap = argparse.ArgumentParser(description="Vigía — lo escondido en el JS")
    ap.add_argument("outdir")
    ap.add_argument("--include", default="")
    ap.add_argument("--exclude", default="")
    ap.add_argument("--roots", default="")
    a = ap.parse_args()
    out = Path(a.outdir)
    fd = out / "findings"
    jr = fd / "js-raw"
    hd = fd / "hidden"
    hd.mkdir(parents=True, exist_ok=True)
    roots = a.roots or str(out / "roots.txt")
    include = a.include or (str(out / "include.txt") if (out / "include.txt").exists() else "")
    exclude = a.exclude or (str(out / "exclude.txt") if (out / "exclude.txt").exists() else "")
    scope = Scope(include, exclude, roots)
    root_list = [l.strip().lower().lstrip("*.") for l in read(Path(roots)).splitlines() if l.strip()] if Path(roots).exists() else []
    # "misma organización": comparte la etiqueta principal del dominio raíz (p.ej. "acme" en acmehq.com)
    org_labels = {r.split(".")[-2] for r in root_list if r.count(".") >= 1 and len(r.split(".")[-2]) >= 4}

    files = sorted(jr.glob("*.js")) if jr.exists() else []
    cdn = first_party_cdn_hosts(out, scope)
    if cdn:
        print(f"    -> CDN del target (su JS cuenta como propio): {', '.join(sorted(cdn))}", flush=True)
    flags, roles, gql, routes, config, hosts, tmpl = (defaultdict(set) for _ in range(7))
    sdks = defaultdict(set)
    skipped = 0
    for f in files:
        s = read(f)
        if not s:
            continue
        n = f.name[:90]
        if not file_is_target(f.name, scope, cdn):
            skipped += 1
            continue
        for rx in FLAG_RES:
            for m in rx.finditer(s):
                flags[m.group(1)].add(n)
        for m in FLAG_OBJ_RE.finditer(s):
            for k in FLAG_KEY_RE.finditer(m.group(1)):
                flags[k.group(1)].add(n)
        for k in [k for k in flags if k in JS_WORDS or len(k) < 3]:
            del flags[k]
        for m in FLAG_SDK_RE.finditer(s):
            sdks[m.group(1).lower()].add(n)
        for rx in ROLE_RES:
            for m in rx.finditer(s):
                v = m.group(1) + (f" → {m.group(2)}" if m.lastindex and m.lastindex >= 2 and m.group(2) else "")
                roles[v].add(n)
        for m in ROLE_FLAG_RE.finditer(s):
            roles[m.group(1)].add(n)
        for m in GQL_RE.finditer(s):
            gql[f"{m.group(1)} {m.group(2)}"].add(n)
        for m in GQL_OPNAME_RE.finditer(s):
            gql[f"op {m.group(1)}"].add(n)
        for m in GQL_HASH_RE.finditer(s):
            gql[f"persisted sha256:{m.group(1)[:16]}…"].add(n)
        for rx in ROUTE_RES:
            for m in rx.finditer(s):
                r = m.group(1)
                if len(r) > 1 and not NOISE.search(r) and not r.startswith("//"):
                    routes[r if r.startswith("/") else "/" + r].add(n)
        for m in TEMPLATE_URL_RE.finditer(s):
            u = re.sub(r"\$\{[^}]*\}", "{v}", m.group(1))
            if not NOISE.search(u):
                tmpl[u].add(n)
        for rx in CONFIG_RES:
            for m in rx.finditer(s):
                config[f"{m.group(1)} = {m.group(2)}"].add(n)
        for m in HOST_RE.finditer(s):
            h = m.group(1).lower().rstrip(".")
            tld = h.split(".")[-1]
            if len(tld) < 2 or tld in ("js", "mjs", "css", "json", "map", "png", "svg", "html", "php"):
                continue
            hosts[h].add(n)

    # __NEXT_DATA__ y rutas de la app que sacó el crawl
    for cf in (out / "crawl").glob("*.json") if (out / "crawl").exists() else []:
        try:
            j = json.loads(read(cf))
        except Exception:
            continue
        nd = (j.get("manifest") or {}).get("nextData") or ""
        if nd:
            try:
                d = json.loads(nd)
                for k in ("runtimeConfig", "publicRuntimeConfig", "env"):
                    if isinstance(d.get(k), dict):
                        for kk, vv in d[k].items():
                            config[f"__NEXT_DATA__.{k}.{kk} = {str(vv)[:200]}"].add(cf.name[:60])
                for m in HOST_RE.finditer(nd):
                    hosts[m.group(1).lower()].add("__NEXT_DATA__")
            except Exception:
                pass
    for l in read(fd / "app-routes.txt").splitlines():
        p = "/" + l.split("/", 1)[1] if "/" in l else l
        routes[p.split("   ")[0]].add("mapa de la app (crawl)")

    # hosts: clasificar
    h_in, h_org, h_3rd = {}, {}, {}
    for h, src in hosts.items():
        if scope.host_ok(h):
            h_in[h] = src
        elif any(lbl in h.split(".") or f"{lbl}-" in h or f"-{lbl}" in h for lbl in org_labels) and not THIRD_PARTY.search(h):
            h_org[h] = src
        else:
            h_3rd[h] = src

    def dump(name, d, title, key=lambda kv: kv[0]):
        lines = [f"# {title}", f"# {len(d)} entradas · fuente: findings/js-raw (sin tráfico)", ""]
        for k, src in sorted(d.items(), key=key):
            lines.append(f"{k}\t<- {', '.join(sorted(src)[:3])}{' …' if len(src) > 3 else ''}")
        (hd / name).write_text("\n".join(lines))

    dump("flags.txt", flags, "Feature flags (funciones que existen aunque estén apagadas para ti)")
    dump("roles.txt", roles, "Roles y permisos comprobados en el cliente (¿se comprueban también en el servidor?)")
    dump("graphql-ops.txt", gql, "Operaciones GraphQL con nombre (mutations = acciones)",
         key=lambda kv: (0 if kv[0].startswith("mutation") else 1, kv[0]))
    dump("routes.txt", routes, "Rutas del front (pantallas, aunque no tengan enlace)")
    dump("config.txt", config, "Configuración embebida en el JS")
    hl = ["# Hosts en el JS", "# IN-SCOPE: se pueden mirar. MISMA ORG fuera de scope: NO se tocan (solo contexto).", ""]
    for title, d in (("IN-SCOPE", h_in), ("MISMA ORGANIZACIÓN — FUERA DE SCOPE (no tocar)", h_org), ("TERCEROS", h_3rd)):
        hl.append(f"## {title} ({len(d)})")
        for h in sorted(d, key=lambda x: (0 if INTERNAL_HINT.search(x) else 1, x)):
            hl.append(f"{'[interno?] ' if INTERNAL_HINT.search(h) else ''}{h}\t<- {', '.join(sorted(d[h])[:2])}")
        hl.append("")
    (hd / "hosts.txt").write_text("\n".join(hl))

    # ---- endpoints-top ----
    cands = defaultdict(set)
    for l in read(fd / "endpoints.txt").splitlines():
        ep = l.split("\t")[0].strip()
        if ep:
            cands[ep].add("js")
    for l in read(fd / "js-analysis" / "api-routes.txt").splitlines():
        if l.strip():
            cands[l.strip()].add("js-api")
    for l in read(fd / "js-analysis" / "xnlinkfinder.txt").splitlines():
        if l.strip():
            cands[l.strip()].add("xnlinkfinder")
    for l in read(fd / "api-calls.jsonl").splitlines():
        try:
            x = json.loads(l)
            cands[x["url"]].add(f"API real {x['method']}")
        except Exception:
            pass
    for r in routes:
        cands[r].add("ruta")
    for u in tmpl:
        cands[u].add("plantilla JS")

    def score(ep, src):
        why, sc = [], 0
        if NOISE.search(ep):
            return -99, ["ruido"]
        host = urlparse(ep if "://" in ep else ("https:" + ep if ep.startswith("//") else "https://x" + (ep if ep.startswith("/") else "/" + ep))).hostname or ""
        if "://" in ep or ep.startswith("//"):
            if scope.host_ok(host):
                sc += 2; why.append("in-scope")
            else:
                return -50, ["fuera de scope"]
        if any(s.startswith("API real") for s in src):
            sc += 4; why.append("llamada real")
        if ID_SEG.search(ep):
            sc += 4; why.append("lleva ID (IDOR)")
        if API_HINT.search(ep):
            sc += 2; why.append("API")
        if INTERESTING_PARAM.search(ep):
            sc += 3; why.append("parámetro interesante")
        m = SENSITIVE.search(ep)
        if m:
            sc += 2; why.append(f"sensible: {m.group(1).lower()}")
        if "ruta" in src:
            sc += 1; why.append("pantalla")
        if len(src) > 1:
            sc += 1
        return sc, why

    ranked = sorted(((score(ep, src), ep) for ep, src in cands.items()), key=lambda x: (-x[0][0], x[1]))
    top = [f"{sc:>3}  {ep}   [{', '.join(why)}]" for (sc, why), ep in ranked if sc >= 3][:400]
    (fd / "endpoints-top.txt").write_text(
        "# Endpoints ordenados por interés (puntuación · endpoint · por qué). Pistas, no hallazgos.\n"
        f"# {len(top)} de {len(cands)} candidatos · los agentes empiezan por aquí\n\n" + "\n".join(top))

    # ---- RESUMEN ----
    muts = sorted(k for k in gql if k.startswith("mutation"))
    rs = [f"# Lo escondido — {out.name}", "",
          f"{len(files) - skipped} ficheros JS del target ({skipped} de terceros/librerías ignorados) · {len(flags)} flags · {len(roles)} roles/permisos · {len(gql)} operaciones GraphQL "
          f"({len(muts)} mutations) · {len(routes)} rutas · {len(config)} valores de config · "
          f"hosts: {len(h_in)} in-scope, {len(h_org)} misma org (no tocar), {len(h_3rd)} terceros", ""]
    if sdks:
        rs += [f"SDK de feature flags detectado: {', '.join(sorted(sdks))}", ""]
    def sect(t, items, n=25):
        nonlocal rs
        if items:
            rs += [f"## {t}", ""] + [f"- `{i}`" for i in items[:n]] + ([f"- … y {len(items) - n} más"] if len(items) > n else []) + [""]
    sect("Mutations GraphQL (acciones: ¿quién puede llamarlas?)", muts)
    sect("Rutas con pinta de admin/interno", sorted(r for r in routes if SENSITIVE.search(r) or INTERNAL_HINT.search(r)))
    sect("Roles / permisos en el cliente", sorted(roles))
    sect("Feature flags", sorted(flags))
    sect("Hosts internos o de staging de la misma organización (FUERA DE SCOPE: no tocar)",
         sorted(h for h in h_org if INTERNAL_HINT.search(h)))
    sect("Config con URLs", sorted(c for c in config if "http" in c or "//" in c))
    rs += ["_Pistas, no hallazgos: se cruzan con Atalaya, el mapa de caché y la API real, y las criban los agentes ancla._"]
    (hd / "RESUMEN.md").write_text("\n".join(rs))
    print(f"    -> {len(files) - skipped} JS del target analizados ({skipped} de terceros/librerías ignorados)", flush=True)
    print(f"    -> escondido: {len(flags)} flags · {len(roles)} roles · {len(gql)} GraphQL ({len(muts)} mutations) · "
          f"{len(routes)} rutas · {len(config)} config · hosts {len(h_in)}/{len(h_org)}/{len(h_3rd)} · "
          f"endpoints-top: {len(top)}", flush=True)


if __name__ == "__main__":
    main()
