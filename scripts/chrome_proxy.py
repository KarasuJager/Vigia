#!/usr/bin/env python3
"""
Vigía — Chrome CDP HTTP proxy for Nuclei.

A local HTTP proxy that forwards requests through a real Chrome browser
via CDP (Playwright). This bypasses WAF bot detection (Akamai, Cloudflare)
because the requests are made by a real browser with valid TLS fingerprint
and bot-check cookies.

Usage:
    python3 chrome_proxy.py --ws "ws://..." --port 8888 --handle researcher

Then point Nuclei at it:
    nuclei -proxy http://localhost:8888 -l targets.txt ...

Architecture:
    Nuclei → HTTP proxy (this script) → Chrome CDP → Target (bypasses WAF)
"""
import argparse
import asyncio
import json
import re
import signal
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
import urllib.request
import threading

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
            return ws_url
    except Exception:
        pass
    return endpoint


class ChromeProxyState:
    """Shared state between the sync HTTP server and the async browser."""
    def __init__(self):
        self.loop = None
        self.browser_ctx = None
        self.request_count = 0
        self.error_count = 0
        self.lock = threading.Lock()
        self.rate_limit = 10  # requests per second
        self.last_request_time = 0
        self.handle = "researcher"
        self.contact = ""


STATE = ChromeProxyState()


class ProxyHandler(BaseHTTPRequestHandler):
    """HTTP proxy handler — forwards requests through Chrome CDP."""

    def do_GET(self):
        self._proxy_request("GET")

    def do_POST(self):
        self._proxy_request("POST")

    def do_PUT(self):
        self._proxy_request("PUT")

    def do_DELETE(self):
        self._proxy_request("DELETE")

    def do_HEAD(self):
        self._proxy_request("HEAD")

    def do_OPTIONS(self):
        self._proxy_request("OPTIONS")

    def do_PATCH(self):
        self._proxy_request("PATCH")

    def do_CONNECT(self):
        """CONNECT method (HTTPS tunneling) — not supported through Chrome CDP."""
        self.send_error(501, "CONNECT not supported — use HTTP URLs with Nuclei (-dreq)")
        return

    def _proxy_request(self, method):
        url = self.path
        if not url.startswith("http"):
            self.send_error(400, "Proxy requires absolute URL")
            return

        # Read body if present
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else None

        # Collect headers (skip hop-by-hop)
        skip_headers = {
            "host", "proxy-connection", "proxy-authorization",
            "connection", "keep-alive", "transfer-encoding",
            "te", "trailer", "upgrade",
        }
        headers = {}
        for key, value in self.headers.items():
            if key.lower() not in skip_headers:
                headers[key] = value

        # Add identification headers
        ua = f"bugbounty-{STATE.handle}"
        if STATE.contact:
            ua += f" (+{STATE.contact})"
        headers["User-Agent"] = ua
        headers["X-Bug-Bounty"] = STATE.handle

        # Execute through Chrome in the async loop
        future = asyncio.run_coroutine_threadsafe(
            self._chrome_fetch(method, url, headers, body),
            STATE.loop
        )

        try:
            status, resp_headers, resp_body = future.result(timeout=60)
        except Exception as e:
            with STATE.lock:
                STATE.error_count += 1
            self.send_error(502, f"Chrome proxy error: {str(e)[:200]}")
            return

        with STATE.lock:
            STATE.request_count += 1

        # Send response back to Nuclei
        self.send_response(status)
        for key, value in resp_headers.items():
            if key.lower() not in ("transfer-encoding", "content-encoding",
                                    "content-length"):
                self.send_header(key, value)
        if resp_body:
            self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        if resp_body:
            self.wfile.write(resp_body)

    async def _chrome_fetch(self, method, url, headers, body):
        """Execute a single request through Chrome's browser context."""
        # Rate limiting
        await asyncio.sleep(1.0 / STATE.rate_limit)

        ctx = STATE.browser_ctx
        try:
            resp = await ctx.request.fetch(
                url,
                method=method,
                headers=headers,
                data=body,
                timeout=30000,
                ignore_https_errors=True,
            )
            status = resp.status
            resp_headers = await resp.all_headers()
            resp_body = await resp.body()
            return status, resp_headers, resp_body
        except Exception as e:
            # Return 502 with error info
            error_body = json.dumps({"error": str(e)}).encode()
            return 502, {"content-type": "application/json"}, error_body

    def log_message(self, format, *args):
        """Suppress default logging — we print our own stats."""
        pass


async def run_browser(ws_endpoint, handle, contact):
    """Start the browser context and keep it alive."""
    async with async_playwright() as p:
        ws = resolve_cdp_ws(ws_endpoint)
        print(f"[proxy] Connecting to Chrome: {ws}", flush=True)
        browser = await p.chromium.connect_over_cdp(ws)

        ua = f"bugbounty-{handle}"
        if contact:
            ua += f" (+{contact})"

        STATE.browser_ctx = await browser.new_context(
            user_agent=ua,
            extra_http_headers={"X-Bug-Bounty": handle},
            ignore_https_errors=True,
        )
        print("[proxy] Chrome context ready", flush=True)

        # Keep alive until interrupted
        try:
            while True:
                await asyncio.sleep(10)
                with STATE.lock:
                    if STATE.request_count > 0 or STATE.error_count > 0:
                        print(f"[proxy] Stats: {STATE.request_count} proxied, "
                              f"{STATE.error_count} errors", flush=True)
        except asyncio.CancelledError:
            pass
        finally:
            await STATE.browser_ctx.close()
            await browser.close()


def run_http_server(port):
    """Run the HTTP proxy server in a thread."""
    server = HTTPServer(("0.0.0.0", port), ProxyHandler)
    print(f"[proxy] Listening on 0.0.0.0:{port}", flush=True)
    server.serve_forever()


def main():
    ap = argparse.ArgumentParser(
        description="Chrome CDP HTTP proxy for Nuclei WAF bypass")
    ap.add_argument("--ws", required=True,
                    help="Chrome CDP WebSocket or HTTP endpoint")
    ap.add_argument("--port", type=int, default=8888,
                    help="Proxy listen port (default: 8888)")
    ap.add_argument("--rate-limit", type=int, default=10,
                    help="Max requests/sec through Chrome (default: 10)")
    ap.add_argument("--handle", default="researcher",
                    help="Bug bounty handle for UA identification")
    ap.add_argument("--contact", default="",
                    help="Contact info appended to UA")
    args = ap.parse_args()

    STATE.rate_limit = args.rate_limit
    STATE.handle = args.handle
    STATE.contact = args.contact

    print(f"""
╔══════════════════════════════════════════════╗
║  Vigía Chrome Proxy for Nuclei              ║
║  WAF bypass via real Chrome browser         ║
╠══════════════════════════════════════════════╣
║  Proxy:      http://0.0.0.0:{args.port:<14s}  ║
║  Rate limit: {args.rate_limit} req/s{' ' * 25}║
║  Handle:     {args.handle:<30s} ║
╚══════════════════════════════════════════════╝
""", flush=True)

    # Start HTTP server in background thread
    server_thread = threading.Thread(target=run_http_server, args=(args.port,),
                                     daemon=True)
    server_thread.start()

    # Run browser event loop in main thread
    loop = asyncio.new_event_loop()
    STATE.loop = loop

    try:
        loop.run_until_complete(run_browser(args.ws, args.handle, args.contact))
    except KeyboardInterrupt:
        print("\n[proxy] Shutting down...", flush=True)
    finally:
        loop.close()


if __name__ == "__main__":
    main()
