# Vigía — recon + JS deep analysis toolbox
# Multi-stage: compile JSLuice with Go, then copy binary to slim image.

# ---- Stage 1: Build Go tools ----
FROM golang:1.22-bookworm AS go-builder
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*
RUN CGO_ENABLED=1 go install github.com/BishopFox/jsluice/cmd/jsluice@latest
RUN go install github.com/tomnomnom/qsreplace@latest
RUN go install github.com/hahwul/dalfox/v2@latest

# ---- Stage 2: Main image ----
FROM python:3.12-slim-bookworm

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl jq unzip tar gzip bash git nodejs npm \
 && rm -rf /var/lib/apt/lists/*

# Playwright client + jsbeautifier
RUN pip install --no-cache-dir playwright==1.48.0 jsbeautifier

# RetireJS
RUN npm install -g retire

# LinkFinder + SecretFinder
RUN git clone --depth 1 https://github.com/dark-warlord14/LinkFinder.git /opt/LinkFinder \
 && pip install --no-cache-dir -r /opt/LinkFinder/requirements.txt \
 && git clone --depth 1 https://github.com/m4ll0k/SecretFinder.git /opt/SecretFinder \
 && pip install --no-cache-dir -r /opt/SecretFinder/requirements.txt

# Go tools from builder stage
COPY --from=go-builder /go/bin/jsluice /usr/local/bin/jsluice
COPY --from=go-builder /go/bin/qsreplace /usr/local/bin/qsreplace
COPY --from=go-builder /go/bin/dalfox /usr/local/bin/dalfox

# Recon tools (subfinder, httpx, amass)
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
    get projectdiscovery/nuclei    nuclei; \
    get owasp-amass/amass          amass

# Nuclei templates (only critical + high + exposed-panels + cves)
RUN nuclei -update-templates 2>/dev/null || true

WORKDIR /app
COPY scripts/ /app/scripts/
RUN chmod +x /app/scripts/*.sh

ENTRYPOINT ["/app/scripts/entrypoint.sh"]
CMD []
