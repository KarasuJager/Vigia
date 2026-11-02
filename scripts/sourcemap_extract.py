#!/usr/bin/env python3
"""
Vigía — Source Map Extractor

Busca y descarga source maps (.js.map) de los JS descubiertos por el crawl.
Si los encuentra, extrae los archivos fuente originales para que js_analyze.py
los analice junto con los JS minificados.

Se ejecuta ENTRE crawl_extract.py y js_analyze.py en recon.sh.
Si no encuentra source maps, no afecta al resto del pipeline.

Uso:
  python sourcemap_extract.py <vigia-output-dir> [--handle researcher] [--delay-ms 300]
"""

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests

# ════════════════════════════════════════════════════════════
# HELPERS
# ════════════════════════════════════════════════════════════

SOURCEMAP_RE = re.compile(r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)')


def safe_name(url: str) -> str:
    """Reproduce la función safe_name de crawl_extract.py."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", url)[:150]


def find_sourcemap_url_in_content(js_content: str) -> str | None:
    """Busca //# sourceMappingURL=... en el contenido del JS."""
    # Mirar las últimas 5 líneas (lo más común) y las primeras 3
    lines = js_content.splitlines()
    search_lines = lines[-5:] + lines[:3]
    for line in search_lines:
        m = SOURCEMAP_RE.search(line)
        if m:
            url = m.group(1).strip()
            # Ignorar data: URIs (source maps inline — ya están en el JS)
            if url.startswith("data:"):
                return None
            return url
    return None


def build_js_url_map(crawl_dir: Path) -> dict[str, str]:
    """
    Lee los JSONs del crawl y construye un mapping:
      safe_name(js_url) + ".js"  →  js_url original
    """
    mapping = {}
    if not crawl_dir.exists():
        return mapping

    for json_file in crawl_dir.glob("*.json"):
        try:
            data = json.loads(json_file.read_text(errors="replace"))
        except Exception:
            continue

        js_urls = set()
        for u in data.get("scripts", []) + data.get("resources", []):
            if u.split("?")[0].lower().endswith(".js"):
                js_urls.add(u)

        for js_url in js_urls:
            key = safe_name(js_url) + ".js"
            mapping[key] = js_url

    return mapping


def resolve_map_url(sourcemap_ref: str, js_url: str) -> str:
    """Resuelve la URL del source map (absoluta o relativa al JS)."""
    if sourcemap_ref.startswith(("http://", "https://", "//")):
        # URL absoluta
        if sourcemap_ref.startswith("//"):
            parsed = urlparse(js_url)
            return f"{parsed.scheme}:{sourcemap_ref}"
        return sourcemap_ref

    # URL relativa → resolver contra la URL del JS
    return urljoin(js_url, sourcemap_ref)


def download(url: str, handle: str, timeout: int = 15,
             verify: bool = True) -> tuple[int, str]:
    """Descarga una URL y devuelve (status, body)."""
    try:
        resp = requests.get(
            url,
            headers={
                "User-Agent": f"bugbounty-{handle}",
                "X-Bug-Bounty": handle,
            },
            timeout=timeout,
            verify=verify,
        )
        return resp.status_code, resp.text
    except Exception:
        return 0, ""


def extract_sources(map_data: dict) -> list[dict]:
    """
    Extrae los archivos fuente de un source map.
    Devuelve lista de {name, content}.
    """
    sources = map_data.get("sources", [])
    contents = map_data.get("sourcesContent", [])
    extracted = []

    for i, name in enumerate(sources):
        if i < len(contents) and contents[i]:
            # Limpiar el nombre del archivo
            clean_name = name.lstrip("./\\")
            # Quitar webpack:// y similares
            for prefix in ["webpack://", "webpack:///", "turbopack://",
                           "vite://", "file://", "app:///"]:
                if clean_name.startswith(prefix):
                    clean_name = clean_name[len(prefix):]
            clean_name = clean_name.lstrip("./\\")

            if clean_name and contents[i].strip():
                extracted.append({
                    "name": clean_name,
                    "content": contents[i],
                })

    return extracted


# ════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        description="Vigía — Source Map Extractor")
    ap.add_argument("outdir",
                    help="VIGÍA output directory (e.g. data/target/20261102-010000)")
    ap.add_argument("--handle", default="researcher",
                    help="Bug bounty handle for User-Agent")
    ap.add_argument("--delay-ms", type=int, default=300,
                    help="Delay between requests (ms)")
    ap.add_argument("--no-verify-ssl", action="store_true",
                    help="Ignore SSL errors")
    args = ap.parse_args()

    out = Path(args.outdir)
    js_raw = out / "findings" / "js-raw"
    crawl_dir = out / "crawl"
    smap_dir = out / "findings" / "js-sourcemaps"

    if not js_raw.exists():
        print("[!] No js-raw directory found — run crawl first")
        sys.exit(1)

    js_files = sorted(js_raw.glob("*.js"))
    # No procesar archivos que ya son extracciones de source maps
    js_files = [f for f in js_files if not f.name.startswith("smap_")]

    if not js_files:
        print("[!] No JS files found in js-raw/")
        sys.exit(0)

    print(f"[*] Source Map Extractor — {len(js_files)} JS files")

    # 1. Construir mapping filename → URL original
    url_map = build_js_url_map(crawl_dir)
    print(f"    URL mapping: {len(url_map)} JS URLs from crawl data")

    # 2. Para cada JS, buscar source map
    smap_dir.mkdir(parents=True, exist_ok=True)
    found_maps = 0
    total_sources = 0
    results = []

    for jsf in js_files:
        js_content = jsf.read_text(errors="replace")
        js_url = url_map.get(jsf.name, "")

        # Buscar sourceMappingURL en el contenido
        smap_ref = find_sourcemap_url_in_content(js_content)

        # Candidatos de URL del .map
        candidates = []
        if smap_ref and js_url:
            candidates.append(("sourceMappingURL", resolve_map_url(smap_ref, js_url)))
        elif smap_ref and smap_ref.startswith(("http://", "https://")):
            candidates.append(("sourceMappingURL", smap_ref))

        # Fallback: intentar <js_url>.map
        if js_url:
            map_url = js_url.split("?")[0] + ".map"
            if map_url not in [c[1] for c in candidates]:
                candidates.append(("fallback", map_url))

        if not candidates:
            continue

        # Intentar descargar
        for source, map_url in candidates:
            time.sleep(args.delay_ms / 1000)
            status, body = download(map_url, args.handle,
                                    verify=not args.no_verify_ssl)

            if status != 200 or not body.strip().startswith("{"):
                continue

            # Parsear el source map
            try:
                map_data = json.loads(body)
            except json.JSONDecodeError:
                continue

            if "sources" not in map_data:
                continue

            # ¡Source map encontrado!
            found_maps += 1
            sources = extract_sources(map_data)
            total_sources += len(sources)

            short_name = jsf.name[:60]
            print(f"  🗺️  {short_name}")
            print(f"      via: {source}")
            print(f"      {len(sources)} archivos fuente extraídos")

            # Guardar el .map completo
            map_filename = safe_name(map_url) + ".map"
            (smap_dir / map_filename).write_text(body)

            # Guardar cada archivo fuente
            js_count = 0
            for src in sources:
                src_filename = safe_name(src["name"])
                # Guardar en js-sourcemaps/ con estructura
                src_path = smap_dir / src_filename
                src_path.write_text(src["content"], errors="replace")

                # Si es JS/TS/JSX/TSX/Vue, copiar a js-raw/ con prefijo smap_
                # para que js_analyze.py lo analice automáticamente
                ext = os.path.splitext(src["name"])[1].lower()
                if ext in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue"):
                    raw_copy = js_raw / f"smap_{src_filename}.js"
                    raw_copy.write_text(src["content"], errors="replace")
                    js_count += 1

            print(f"      {js_count} copiados a js-raw/ para análisis")

            results.append({
                "js_file": jsf.name,
                "js_url": js_url,
                "map_url": map_url,
                "source": source,
                "files_extracted": len(sources),
                "js_files_for_analysis": js_count,
                "source_names": [s["name"] for s in sources[:50]],
            })

            # No seguir probando candidatos para este JS
            break

    # 3. Resumen
    summary = {
        "js_files_checked": len(js_files),
        "sourcemaps_found": found_maps,
        "source_files_extracted": total_sources,
        "results": results,
    }
    (smap_dir / "sourcemap-summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False))

    print(f"\n{'═' * 50}")
    if found_maps > 0:
        print(f"  🗺️  {found_maps} source map(s) encontrados")
        print(f"  📄 {total_sources} archivos fuente extraídos")
        print(f"  → js_analyze.py los procesará automáticamente")
    else:
        print(f"  ✓ {len(js_files)} JS revisados — sin source maps accesibles")
        print(f"  (esto es normal — muchos targets no los exponen)")
    print(f"{'═' * 50}")


if __name__ == "__main__":
    main()
