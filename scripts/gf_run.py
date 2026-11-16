#!/usr/bin/env python3
"""
Vigía — getfrontend con correa (zb3/getfrontend, sin tocar su código).

getfrontend encuentra los chunks de webpack/vite/Next/Remix que el navegador NUNCA pidió
(pantallas que no visitamos) y sus source maps. De serie: 3 hilos, sin límite de velocidad y
reintentos INFINITOS ante 429/5xx. Aquí se le pone la correa:
  - 1 hilo y una pausa fija entre peticiones (el ritmo del programa: --delay-ms)
  - máximo 2 reintentos; si el sitio bloquea (403/429/503) varias veces seguidas, se para
  - tope de peticiones por ejecución (--max-requests)
  - solo pide a los orígenes que le pasamos (los que el navegador ya cargó, del target)
  - siempre con nuestra identificación (User-Agent + cabecera)
Los JS (y fuentes reconstruidos) acaban en findings/js-raw/gf_<host>_... para el resto del pipeline.

Uso: gf_run.py <run-dir> --ua UA --ident-header H --handle X --delay-ms N [--max-requests N] [--include f] [--exclude f]
"""
import argparse, hashlib, json, re, shutil, sys, tempfile, threading, time
from pathlib import Path
from urllib.parse import urlparse

GF_DIR = "/opt/getfrontend"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir")
    ap.add_argument("--ua", required=True)
    ap.add_argument("--ident-header", default="X-Bug-Bounty")
    ap.add_argument("--handle", required=True)
    ap.add_argument("--delay-ms", type=int, default=1000)
    ap.add_argument("--max-requests", type=int, default=400)
    ap.add_argument("--max-roots", type=int, default=10)
    ap.add_argument("--include", default="")
    ap.add_argument("--exclude", default="")
    ap.add_argument("--roots", default="")
    ap.add_argument("--gf-dir", default=GF_DIR)
    a = ap.parse_args()

    sys.path.insert(0, a.gf_dir)
    sys.path.insert(0, str(Path(__file__).parent))
    try:
        import getfrontend as gfm
    except Exception as e:
        print(f"    [getfrontend] no instalado ({e}) — se salta", flush=True)
        return
    from crawl_extract import Scope, safe_name
    out = Path(a.outdir)
    scope = Scope(a.include or (str(out / "include.txt") if (out / "include.txt").exists() else ""),
                  a.exclude or (str(out / "exclude.txt") if (out / "exclude.txt").exists() else ""),
                  a.roots or str(out / "roots.txt"))

    # --- la correa ---
    lock = threading.Lock()
    state = {"last": 0.0, "n": 0, "blocks": 0, "stop": False}
    delay = max(a.delay_ms, 200) / 1000

    def leashed_request(self, method, url, *args, **kwargs):
        for attempt in range(3):                       # 1 intento + 2 reintentos, nunca infinito
            with lock:
                if state["stop"] or state["n"] >= a.max_requests:
                    return None
                wait = state["last"] + delay - time.time()
                if wait > 0:
                    time.sleep(wait)
                state["last"] = time.time()
                state["n"] += 1
            try:
                res = self.rs.request(method, url, *args, timeout=self.timeout, **kwargs)
            except Exception:
                continue
            if res.status_code in (403, 429, 503):
                with lock:
                    state["blocks"] += 1
                    if state["blocks"] >= 5:
                        state["stop"] = True
                        print("    [getfrontend] 5 bloqueos (403/429/503): paro", flush=True)
                return res
            if res.status_code in (408, 500, 502, 504):
                continue
            with lock:
                state["blocks"] = 0
            return res
        return None

    try:
        gfm.log.level = -10                            # sin su log por fichero (ruido en el log del run)
    except Exception:
        pass
    gfm.Client.request = leashed_request
    _Fetcher = gfm.Fetcher

    class OneWorker(_Fetcher):
        def __init__(self, client, n_workers):
            super().__init__(client, 1)
    gfm.Fetcher = OneWorker

    # --- raíces: páginas del crawl que cargaron JS del propio target ---
    roots, origins = [], set()
    for cf in sorted((out / "crawl").glob("*.json")):
        try:
            j = json.loads(cf.read_text(errors="replace"))
        except Exception:
            continue
        st = j.get("status")
        if not (isinstance(st, int) and 200 <= st < 400) or j.get("blocked") or j.get("out_of_scope_root"):
            continue
        js = [u for u in j.get("scripts", []) + j.get("resources", []) if u.split("?")[0].endswith((".js", ".mjs"))]
        own = [u for u in js if scope.url_ok(u)]
        if not own:
            continue
        roots.append(j["url"])
        for u in own:
            p = urlparse(u)
            origins.add(f"{p.scheme}://{p.netloc}")
        p = urlparse(j["url"])
        origins.add(f"{p.scheme}://{p.netloc}")
    roots = roots[: a.max_roots]
    if not roots:
        print("    [getfrontend] ninguna página del target con JS propio — se salta", flush=True)
        return
    print(f"    [getfrontend] {len(roots)} raíces · orígenes permitidos: {', '.join(sorted(origins))} · "
          f"{a.delay_ms} ms/petición · tope {a.max_requests}", flush=True)

    js_raw = out / "findings" / "js-raw"
    js_raw.mkdir(parents=True, exist_ok=True)
    have = {f.name for f in js_raw.glob("*.js")}
    sha = lambda b: hashlib.sha1(b).hexdigest()
    have_hash = set()
    for f in js_raw.glob("*.js"):
        try:
            have_hash.add(sha(f.read_bytes()))
        except Exception:
            pass
    saved = 0
    for root in roots:
        if state["stop"] or state["n"] >= a.max_requests:
            break
        host = urlparse(root).hostname or "x"
        config = {
            "root": root, "origin_whitelist": sorted(origins), "cookies": {},
            "headers": {"User-Agent": a.ua, a.ident_header: a.handle},
            "other_urls": [], "aggressive_mode": False, "ignore_vendor": True,
            "extract_nested_sourcemaps": True, "save_original_assets": False, "all_srcmap_urls": False,
            "no_header_sourcemaps": False, "skip_css": True, "other_asset_extensions": set(),
            "use_original_base": False, "ignore_base_tag": False, "public_path_map": {},
        }
        tmp = Path(tempfile.mkdtemp(prefix="gf_"))
        try:
            gf = gfm.GetFrontend(config)
            gf.run()
            gf.export_to_directory(str(tmp))
        except Exception as e:
            print(f"    [getfrontend] {root}: {str(e)[:120]}", flush=True)
        for f in tmp.rglob("*"):
            if not f.is_file() or f.suffix.lower() not in (".js", ".mjs", ".jsx", ".ts", ".tsx"):
                continue
            rel = str(f.relative_to(tmp))
            if "node_modules" in rel:
                continue
            rel = re.sub(r"^https?_", "", rel)
            name = "gf_" + safe_name(f"https://{host}/{rel}") + ".js"
            try:
                h = sha(f.read_bytes())
            except Exception:
                continue
            if name in have or h in have_hash:          # ya lo bajó el crawl: no duplicar
                continue
            try:
                shutil.copy(f, js_raw / name)
                have.add(name)
                have_hash.add(h)
                saved += 1
            except Exception:
                pass
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"    [getfrontend] {saved} ficheros nuevos a js-raw · {state['n']} peticiones"
          + (" · PARADO por bloqueos" if state["stop"] else ""), flush=True)


if __name__ == "__main__":
    main()
