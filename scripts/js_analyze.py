#!/usr/bin/env python3
"""
Vigía — JS Deep Analysis

Runs after the main recon pipeline. Processes JS files saved in findings/js-raw/
through analysis tools and built-in sink/pattern detection.

Usage:
  python js_analyze.py <vigia-output-dir>
  python js_analyze.py data/moneytree/latest

Tools used (optional — skipped if not installed):
  - jsbeautifier (pip install jsbeautifier) — desminify JS
  - LinkFinder (git clone) — endpoint extraction
  - SecretFinder (git clone) — secret detection
  - RetireJS (npm install -g retire) — vulnerable library detection
  - JSLuice (Docker binary) — deep URL/secret extraction

Built-in (always runs, no deps):
  - Sink detection (innerHTML, eval, postMessage, dangerouslySetInnerHTML, etc.)
  - Auth flow detection (login, token, session, OAuth patterns)
  - Client-only validation detection (disabled, hidden, readonly patterns)
  - Hidden parameter discovery
  - API route extraction
"""
import argparse, json, os, re, subprocess, sys, shutil
from pathlib import Path
from datetime import datetime

# ---- Built-in detection patterns (no external tools needed) -----------------

SINK_PATTERNS = [
    # XSS sinks
    ("XSS_SINK", "innerHTML assignment", re.compile(r'\.innerHTML\s*[=+]', re.I)),
    ("XSS_SINK", "outerHTML assignment", re.compile(r'\.outerHTML\s*[=+]', re.I)),
    ("XSS_SINK", "document.write", re.compile(r'document\.write(ln)?\s*\(', re.I)),
    ("XSS_SINK", "eval()", re.compile(r'\beval\s*\(', re.I)),
    ("XSS_SINK", "setTimeout string", re.compile(r'setTimeout\s*\(\s*["\']', re.I)),
    ("XSS_SINK", "setInterval string", re.compile(r'setInterval\s*\(\s*["\']', re.I)),
    ("XSS_SINK", "new Function()", re.compile(r'new\s+Function\s*\(', re.I)),
    ("XSS_SINK", "dangerouslySetInnerHTML", re.compile(r'dangerouslySetInnerHTML', re.I)),
    ("XSS_SINK", "v-html directive", re.compile(r'v-html\s*=', re.I)),
    ("XSS_SINK", "bypassSecurityTrustHtml", re.compile(r'bypassSecurityTrustHtml', re.I)),
    ("XSS_SINK", "jQuery .html()", re.compile(r'\.\$?\(.*\)\.html\s*\(', re.I)),
    ("XSS_SINK", "jQuery .append() with var", re.compile(r'\.append\s*\(\s*[^"\'<]', re.I)),

    # postMessage sinks (no origin check)
    ("POSTMESSAGE", "postMessage send", re.compile(r'\.postMessage\s*\(', re.I)),
    ("POSTMESSAGE", "message event listener", re.compile(r'addEventListener\s*\(\s*["\']message["\']', re.I)),

    # Prototype pollution
    ("PROTO_POLLUTION", "__proto__ reference", re.compile(r'__proto__', re.I)),
    ("PROTO_POLLUTION", "constructor.prototype", re.compile(r'constructor\s*\[\s*["\']prototype', re.I)),
    ("PROTO_POLLUTION", "Object.assign (potential)", re.compile(r'Object\.assign\s*\(', re.I)),
    ("PROTO_POLLUTION", "lodash merge/defaultsDeep", re.compile(r'_\.(merge|defaultsDeep|set)\s*\(', re.I)),

    # Open redirect sinks
    ("REDIRECT_SINK", "location.href assignment", re.compile(r'location\.href\s*=', re.I)),
    ("REDIRECT_SINK", "location.replace", re.compile(r'location\.replace\s*\(', re.I)),
    ("REDIRECT_SINK", "window.open", re.compile(r'window\.open\s*\(', re.I)),

    # SSRF / fetch sinks
    ("FETCH_SINK", "fetch() with variable", re.compile(r'fetch\s*\(\s*[^"\'h]', re.I)),
    ("FETCH_SINK", "XMLHttpRequest open", re.compile(r'\.open\s*\(\s*["\'](?:GET|POST|PUT|DELETE)', re.I)),
    ("FETCH_SINK", "axios with variable", re.compile(r'axios\.(get|post|put|delete|request)\s*\(\s*[^"\']', re.I)),
]

AUTH_PATTERNS = [
    ("AUTH_FLOW", "token storage", re.compile(r'localStorage\.setItem\s*\(\s*["\'].*(?:token|jwt|auth|session)', re.I)),
    ("AUTH_FLOW", "token retrieval", re.compile(r'localStorage\.getItem\s*\(\s*["\'].*(?:token|jwt|auth|session)', re.I)),
    ("AUTH_FLOW", "authorization header", re.compile(r'["\']Authorization["\']\s*:\s*["\']Bearer', re.I)),
    ("AUTH_FLOW", "cookie manipulation", re.compile(r'document\.cookie\s*=', re.I)),
    ("AUTH_FLOW", "OAuth/OIDC pattern", re.compile(r'(?:client_id|redirect_uri|response_type|grant_type|code_verifier)', re.I)),
    ("AUTH_FLOW", "password field reference", re.compile(r'["\'](?:password|passwd|current_password|old_password|new_password)["\']', re.I)),
]

CLIENT_VALIDATION_PATTERNS = [
    ("CLIENT_ONLY", "disabled attribute toggle", re.compile(r'\.disabled\s*=\s*(true|false)', re.I)),
    ("CLIENT_ONLY", "readonly toggle", re.compile(r'\.readOnly\s*=', re.I)),
    ("CLIENT_ONLY", "hidden field", re.compile(r'type\s*[=:]\s*["\']hidden["\']', re.I)),
    ("CLIENT_ONLY", "client-side price/amount", re.compile(r'(?:price|amount|total|discount|quantity)\s*[=:]\s*\d', re.I)),
    ("CLIENT_ONLY", "role/permission check client-side", re.compile(r'(?:isAdmin|is_admin|role|permission)\s*[=!]==?\s*["\']', re.I)),
    ("CLIENT_ONLY", "max/min validation", re.compile(r'(?:maxLength|minLength|max|min)\s*[=:]\s*\d', re.I)),
]

HIDDEN_PARAM_RE = re.compile(
    r"""(?:["'])((?:debug|test|admin|internal|hidden|secret|private|dev|staging|beta|preview|verbose|mode|flag|feature|toggle|config|override|force|bypass|skip|disable|enable|raw|source|draft|unpublished|include_deleted|show_all|full|extended|detailed|x-|_)[a-zA-Z0-9_-]*)(?:["'])""",
    re.I
)

API_ROUTE_RE = re.compile(
    r"""["']((?:/api/|/v[0-9]+/|/rest/|/graphql|/internal/|/admin/|/private/)[^"'><,;\s]{2,})["']""",
    re.I
)


def analyze_file(filepath, filename):
    """Analyze a single JS file with built-in patterns."""
    try:
        content = filepath.read_text(errors="replace")
    except Exception:
        return []

    findings = []
    lines = content.split("\n")

    for category, label, pattern in SINK_PATTERNS + AUTH_PATTERNS + CLIENT_VALIDATION_PATTERNS:
        for i, line in enumerate(lines, 1):
            for m in pattern.finditer(line):
                context = line.strip()[:200]
                findings.append({
                    "category": category,
                    "label": label,
                    "file": filename,
                    "line": i,
                    "match": m.group(0)[:100],
                    "context": context
                })

    # Hidden parameters
    for m in HIDDEN_PARAM_RE.finditer(content):
        findings.append({
            "category": "HIDDEN_PARAM",
            "label": "potential hidden parameter",
            "file": filename,
            "line": 0,
            "match": m.group(1),
            "context": ""
        })

    # API routes
    for m in API_ROUTE_RE.finditer(content):
        findings.append({
            "category": "API_ROUTE",
            "label": "API endpoint in JS",
            "file": filename,
            "line": 0,
            "match": m.group(1),
            "context": ""
        })

    return findings


def run_tool(name, cmd, cwd=None):
    """Run an external tool, return output or None if not installed."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, cwd=cwd)
        return result.stdout
    except FileNotFoundError:
        print(f"    [{name}] not installed — skipping")
        return None
    except subprocess.TimeoutExpired:
        print(f"    [{name}] timed out — skipping")
        return None
    except Exception as e:
        print(f"    [{name}] error: {e}")
        return None


def main():
    ap = argparse.ArgumentParser(description="Vigía JS Deep Analysis")
    ap.add_argument("outdir", help="VIGÍA output directory (e.g. data/target/latest)")
    ap.add_argument("--linkfinder", default="", help="Path to linkfinder.py")
    ap.add_argument("--secretfinder", default="", help="Path to SecretFinder.py")
    ap.add_argument("--jsluice", default="", help="Path to jsluice binary (or 'docker')")
    args = ap.parse_args()

    out = Path(args.outdir)
    js_raw = out / "findings" / "js-raw"
    js_analysis = out / "findings" / "js-analysis"

    if not js_raw.exists() or not list(js_raw.glob("*.js")):
        print(f"[!] No JS files found in {js_raw}")
        print("    Run VIGÍA first, or check the path.")
        sys.exit(1)

    js_files = sorted(js_raw.glob("*.js"))
    print(f"[*] JS Deep Analysis — {len(js_files)} files in {js_raw}")
    print(f"    Output: {js_analysis}")

    # Create output dirs
    beautified_dir = js_analysis / "beautified"
    beautified_dir.mkdir(parents=True, exist_ok=True)

    # ---- Step 1: Beautify (desminify) ----
    print("\n[1/6] Desminifying JS files...")
    try:
        import jsbeautifier
        opts = jsbeautifier.default_options()
        opts.indent_size = 2
        for jsf in js_files:
            content = jsf.read_text(errors="replace")
            beautified = jsbeautifier.beautify(content, opts)
            (beautified_dir / jsf.name).write_text(beautified)
        print(f"    -> {len(js_files)} files beautified")
        # Use beautified files for analysis
        analysis_files = sorted(beautified_dir.glob("*.js"))
    except ImportError:
        print("    jsbeautifier not installed (pip install jsbeautifier) — using raw files")
        analysis_files = js_files

    # ---- Step 2: Built-in sink/pattern analysis ----
    print("\n[2/6] Built-in sink & pattern analysis...")
    all_findings = []
    for jsf in analysis_files:
        findings = analyze_file(jsf, jsf.name)
        all_findings.extend(findings)

    # Group by category
    by_cat = {}
    for f in all_findings:
        by_cat.setdefault(f["category"], []).append(f)

    # Write findings report
    report_lines = [f"# Vigía JS Deep Analysis", f"# Generated: {datetime.now().isoformat()}Z",
                    f"# Files analyzed: {len(analysis_files)}", f"# Total findings: {len(all_findings)}", ""]

    for cat in ["XSS_SINK", "POSTMESSAGE", "PROTO_POLLUTION", "REDIRECT_SINK", "FETCH_SINK",
                "AUTH_FLOW", "CLIENT_ONLY", "HIDDEN_PARAM", "API_ROUTE"]:
        items = by_cat.get(cat, [])
        report_lines.append(f"\n## {cat} ({len(items)} findings)")
        report_lines.append("-" * 60)
        seen = set()
        for f in items:
            key = (f["label"], f["file"], f["match"])
            if key in seen:
                continue
            seen.add(key)
            if f["line"]:
                report_lines.append(f"  [{f['label']}] {f['file']}:{f['line']}")
                if f["context"]:
                    report_lines.append(f"    > {f['context']}")
            else:
                report_lines.append(f"  [{f['label']}] {f['match']}")
        if not items:
            report_lines.append("  (none)")

    (js_analysis / "builtin-analysis.txt").write_text("\n".join(report_lines))
    print(f"    -> {len(all_findings)} findings across {len(by_cat)} categories")

    # Write separate files for key categories
    api_routes = sorted(set(f["match"] for f in all_findings if f["category"] == "API_ROUTE"))
    (js_analysis / "api-routes.txt").write_text("\n".join(api_routes))
    print(f"    -> {len(api_routes)} API routes extracted")

    hidden_params = sorted(set(f["match"] for f in all_findings if f["category"] == "HIDDEN_PARAM"))
    (js_analysis / "hidden-params.txt").write_text("\n".join(hidden_params))
    print(f"    -> {len(hidden_params)} potential hidden parameters")

    sinks = [f for f in all_findings if f["category"] in ("XSS_SINK", "POSTMESSAGE", "PROTO_POLLUTION", "REDIRECT_SINK", "FETCH_SINK")]
    print(f"    -> {len(sinks)} dangerous sinks found")

    # ---- Step 3: LinkFinder ----
    print("\n[3/6] LinkFinder...")
    lf_path = args.linkfinder or shutil.which("linkfinder") or ""
    if not lf_path:
        # Try common locations
        for p in ["/opt/LinkFinder/linkfinder.py",
                  os.path.expanduser("~/LinkFinder/linkfinder.py"),
                  os.path.expanduser("~/tools/LinkFinder/linkfinder.py")]:
            if os.path.exists(p):
                lf_path = p
                break
    if lf_path and os.path.exists(lf_path):
        lf_results = []
        for jsf in js_files[:50]:  # Cap to avoid timeout
            out_text = run_tool("LinkFinder", ["python3", lf_path, "-i", str(jsf), "-o", "cli"])
            if out_text:
                lf_results.append(f"# {jsf.name}\n{out_text}")
        if lf_results:
            (js_analysis / "linkfinder.txt").write_text("\n".join(lf_results))
            print(f"    -> results written to linkfinder.txt")
    else:
        print("    LinkFinder not found — skipping")

    # ---- Step 4: SecretFinder ----
    print("\n[4/6] SecretFinder...")
    sf_path = args.secretfinder or ""
    if not sf_path:
        for p in ["/opt/SecretFinder/SecretFinder.py",
                  os.path.expanduser("~/SecretFinder/SecretFinder.py"),
                  os.path.expanduser("~/tools/SecretFinder/SecretFinder.py")]:
            if os.path.exists(p):
                sf_path = p
                break
    if sf_path and os.path.exists(sf_path):
        sf_results = []
        for jsf in js_files[:50]:
            out_text = run_tool("SecretFinder", ["python3", sf_path, "-i", str(jsf), "-o", "cli"])
            if out_text:
                sf_results.append(f"# {jsf.name}\n{out_text}")
        if sf_results:
            (js_analysis / "secretfinder.txt").write_text("\n".join(sf_results))
            print(f"    -> results written to secretfinder.txt")
    else:
        print("    SecretFinder not found — skipping")

    # ---- Step 5: RetireJS ----
    print("\n[5/6] RetireJS...")
    retire_path = shutil.which("retire") or ""
    if not retire_path:
        for p in [os.path.expanduser("~/tools/node_modules/.bin/retire"),
                  os.path.expanduser("~/node_modules/.bin/retire")]:
            if os.path.exists(p):
                retire_path = p
                break
    if retire_path:
        out_text = run_tool("RetireJS", [retire_path, "--path", str(js_raw), "--outputformat", "json"])
        if out_text:
            (js_analysis / "retirejs.json").write_text(out_text)
            print(f"    -> results written to retirejs.json")
    else:
        print("    RetireJS not found — skipping")

    # ---- Step 6: JSLuice ----
    print("\n[6/6] JSLuice...")
    jsluice_path = args.jsluice or shutil.which("jsluice") or ""
    use_docker = args.jsluice == "docker" or (not jsluice_path)

    jsluice_results = {"urls": [], "secrets": []}
    if jsluice_path and jsluice_path != "docker" and os.path.exists(jsluice_path):
        for jsf in js_files[:50]:
            for mode in ["urls", "secrets"]:
                out_text = run_tool(f"JSLuice-{mode}", [jsluice_path, mode, str(jsf)])
                if out_text:
                    jsluice_results[mode].append(f"# {jsf.name}\n{out_text}")
    elif use_docker and shutil.which("docker"):
        js_raw_abs = str(js_raw.resolve())
        for mode in ["urls", "secrets"]:
            out_text = run_tool(f"JSLuice-{mode}-docker",
                ["docker", "run", "--rm", "-v", f"{js_raw_abs}:/js:ro",
                 "debian:bookworm-slim", "sh", "-c",
                 f"test -x /js/../../../jsluice && find /js -name '*.js' -exec /js/../../../jsluice {mode} {{}} \\;"])
            if out_text:
                jsluice_results[mode].append(out_text)
        if not any(jsluice_results.values()):
            print("    JSLuice not available via Docker — skipping")
    else:
        print("    JSLuice not found — skipping")

    if any(jsluice_results.values()):
        (js_analysis / "jsluice.json").write_text(json.dumps(jsluice_results, indent=2))
        print(f"    -> results written to jsluice.json")

    # ---- Summary ----
    print(f"\n{'='*60}")
    print(f"[+] JS Deep Analysis complete")
    print(f"    Files analyzed:     {len(analysis_files)}")
    print(f"    Sinks found:        {len(sinks)}")
    print(f"    API routes:         {len(api_routes)}")
    print(f"    Hidden params:      {len(hidden_params)}")
    print(f"    Auth patterns:      {len(by_cat.get('AUTH_FLOW', []))}")
    print(f"    Client validations: {len(by_cat.get('CLIENT_ONLY', []))}")
    print(f"    Output:             {js_analysis}")
    print(f"{'='*60}")
    print(f"\nNext: share {js_analysis} with Claude (Mimir) for analysis")


if __name__ == "__main__":
    main()
