# recon toolbox: enum (subfinder, amass, httpx) + crawl/extract driver (Playwright over CDP)
# Uses official precompiled release binaries (linux/amd64 — matches Docker Desktop on Windows/Mac/Linux).
# No Go toolchain, no compiling: fast build, no Go-version drift.

FROM python:3.12-slim-bookworm

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl jq unzip tar gzip bash \
 && rm -rf /var/lib/apt/lists/*

# Playwright client only — we connect to Obscura over CDP, so no browser download needed.
RUN pip install --no-cache-dir playwright==1.48.0

# Pull latest linux/amd64 release binary for each tool via the GitHub API.
# Handles both .zip (projectdiscovery) and .tar.gz (amass v5) assets, any Linux/linux casing.
RUN set -eux; \
    get() { \
      repo="$1"; bin="$2"; \
      assets=$(curl -sSL "https://api.github.com/repos/${repo}/releases/latest" \
               | jq -r '.assets[].browser_download_url'); \
      url=$(echo "$assets" | grep -iE 'linux_amd64\.(zip|tar\.gz)$' | head -n1); \
      if [ -z "$url" ]; then \
        echo "!! No linux_amd64 asset for ${repo}. Available assets:"; echo "$assets"; exit 1; \
      fi; \
      echo "Fetching ${bin} <- ${url}"; \
      curl -sSL "$url" -o /tmp/a.bin; \
      mkdir -p /tmp/un; \
      case "$url" in \
        *.zip)    unzip -o -q /tmp/a.bin -d /tmp/un ;; \
        *.tar.gz) tar xzf /tmp/a.bin -C /tmp/un ;; \
      esac; \
      install -m 0755 "$(find /tmp/un -type f -name "$bin" | head -n1)" "/usr/local/bin/${bin}"; \
      rm -rf /tmp/a.bin /tmp/un; \
      "/usr/local/bin/${bin}" -version 2>&1 | head -n1 || true; \
    }; \
    get projectdiscovery/subfinder subfinder; \
    get projectdiscovery/httpx     httpx; \
    get owasp-amass/amass          amass

WORKDIR /app
COPY scripts/ /app/scripts/
RUN chmod +x /app/scripts/*.sh

ENTRYPOINT ["/bin/bash"]
CMD ["-lc", "./scripts/recon.sh"]
