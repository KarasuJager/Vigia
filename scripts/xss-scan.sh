#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#  VIGÍA — XSS Scanner (3 niveles progresivos)
#
#  Usa las URLs de una run de VIGÍA y busca XSS reflected
#  con dalfox + qsreplace. Cada nivel escala si el anterior
#  no basta.
#
#  Uso:
#    docker compose run --rm recon xss <run-path> [nivel] [--payload "..."] [--payloads-file /path]
#
#  Ejemplos:
#    recon xss /data/target/latest                              # 3 niveles, payloads default
#    recon xss /data/target/latest 1                            # solo nivel 1
#    recon xss /data/target/latest --payload "<svg onload=alert(1)>"
#    recon xss /data/target/latest --payloads-file /scope/mis-payloads.txt
# ============================================================

# ---- Parse arguments ----
RUN_PATH=""
MAX_LEVEL="3"
CUSTOM_PAYLOAD=""
PAYLOADS_FILE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --payload)
            CUSTOM_PAYLOAD="$2"; shift 2 ;;
        --payloads-file)
            PAYLOADS_FILE="$2"; shift 2 ;;
        [1-3])
            MAX_LEVEL="$1"; shift ;;
        *)
            if [ -z "$RUN_PATH" ]; then
                RUN_PATH="$1"
            fi
            shift ;;
    esac
done

if [ -z "$RUN_PATH" ]; then
    echo "[!] Uso: xss-scan.sh <run-path> [nivel] [--payload '...'] [--payloads-file /path]"
    exit 1
fi

if [ ! -d "$RUN_PATH" ]; then
    echo "[!] Run path not found: $RUN_PATH"
    exit 1
fi

HANDLE="${HANDLE:-researcher}"
UA="bugbounty-${HANDLE}"

mkdir -p "$RUN_PATH/findings/xss"

echo "============================================"
echo " VIGÍA — XSS Scanner"
echo " Run: $RUN_PATH"
echo " Max level: $MAX_LEVEL"
echo "============================================"
echo ""

# ---- Recopilar URLs con parámetros ----
echo "[*] Recopilando URLs con parámetros..."

mkdir -p "$RUN_PATH/findings/xss"
URLS_FILE="$RUN_PATH/findings/xss/urls-with-params.txt"
: > "$URLS_FILE"

# De endpoints.txt (VIGÍA crawl)
if [ -f "$RUN_PATH/findings/endpoints.txt" ]; then
    grep '?' "$RUN_PATH/findings/endpoints.txt" >> "$URLS_FILE" 2>/dev/null || true
fi

# De alive_urls.txt
if [ -f "$RUN_PATH/alive_urls.txt" ]; then
    cat "$RUN_PATH/alive_urls.txt" >> "$URLS_FILE" 2>/dev/null || true
fi

# De LinkFinder
if [ -f "$RUN_PATH/findings/js-analysis/linkfinder.txt" ]; then
    grep '?' "$RUN_PATH/findings/js-analysis/linkfinder.txt" >> "$URLS_FILE" 2>/dev/null || true
fi

# Sanitize (strip \r from Windows)
sed -i 's/\r$//' "$URLS_FILE"

# Filter: only URLs from target domains (from roots.txt), not third-party (google, cdn, etc.)
if [ -f "$RUN_PATH/roots.txt" ]; then
    sed 's/\r$//' "$RUN_PATH/roots.txt" > /tmp/roots_clean.txt
    FILTER_PATTERN=$(paste -sd'|' /tmp/roots_clean.txt)
    if [ -n "$FILTER_PATTERN" ]; then
        grep -E "$FILTER_PATTERN" "$URLS_FILE" > "$URLS_FILE.filtered" 2>/dev/null || true
        if [ -s "$URLS_FILE.filtered" ]; then
            mv "$URLS_FILE.filtered" "$URLS_FILE"
        else
            rm -f "$URLS_FILE.filtered"
            echo "    [!] Filter removed all URLs — skipping filter"
        fi
    fi
fi

# Only keep URLs that actually have query parameters
grep '?' "$URLS_FILE" > "$URLS_FILE.params" 2>/dev/null || true
if [ -s "$URLS_FILE.params" ]; then
    mv "$URLS_FILE.params" "$URLS_FILE"
else
    rm -f "$URLS_FILE.params"
fi

sort -u "$URLS_FILE" -o "$URLS_FILE"

URL_COUNT=$(wc -l < "$URLS_FILE")
echo "    -> $URL_COUNT URLs con parámetros (solo target, sin terceros)"

if [ "$URL_COUNT" -eq 0 ]; then
    echo "[!] No hay URLs con parámetros. Nada que escanear."
    exit 0
fi

# ---- Detectar WAF (de wafw00f si existe) ----
WAF_DETECTED=""
if ls "$RUN_PATH"/findings/wafw00f/*.json 2>/dev/null | head -1 > /dev/null; then
    WAF_DETECTED=$(cat "$RUN_PATH"/findings/wafw00f/*.json 2>/dev/null | grep -oP '"firewall":\s*"\K[^"]+' | head -1 || true)
fi
if [ -z "$WAF_DETECTED" ]; then
    # Intentar desde Atalaya si existe
    PROGRAM=$(basename "$(dirname "$RUN_PATH")")
    ATALAYA_WAF="/data/${PROGRAM}/latest/wafw00f"
    if [ -d "$ATALAYA_WAF" ]; then
        WAF_DETECTED=$(cat "$ATALAYA_WAF"/*.json 2>/dev/null | grep -oP '"firewall":\s*"\K[^"]+' | head -1 || true)
    fi
fi

if [ -n "$WAF_DETECTED" ]; then
    echo "[!] WAF detectado: $WAF_DETECTED"
else
    echo "[*] No se detectó WAF"
fi

# Build custom payload flags for dalfox
DALFOX_CUSTOM=""
if [ -n "$CUSTOM_PAYLOAD" ]; then
    DALFOX_CUSTOM="--custom-payload $CUSTOM_PAYLOAD"
    echo "[*] Custom payload: $CUSTOM_PAYLOAD"
fi
if [ -n "$PAYLOADS_FILE" ]; then
    if [ -f "$PAYLOADS_FILE" ]; then
        DALFOX_CUSTOM="--custom-payload-file $PAYLOADS_FILE"
        echo "[*] Custom payloads file: $PAYLOADS_FILE ($(wc -l < "$PAYLOADS_FILE") payloads)"
    else
        echo "[!] Payloads file not found: $PAYLOADS_FILE"
    fi
fi
echo ""

# ════════════════════════════════════════
# NIVEL 1 — Dalfox default (quick wins)
# ════════════════════════════════════════
echo "══════════════════════════════════════════"
echo " Nivel 1 — Dalfox default payloads"
echo "══════════════════════════════════════════"

dalfox file "$URLS_FILE" \
    --silence \
    --no-color \
    --user-agent "$UA" \
    --delay 200 \
    --timeout 10 \
    --only-poc r \
    $DALFOX_CUSTOM \
    -o "$RUN_PATH/findings/xss/nivel1-results.txt" \
    2>/dev/null || true

N1_COUNT=$(wc -l < "$RUN_PATH/findings/xss/nivel1-results.txt" 2>/dev/null || echo 0)
echo "    -> $N1_COUNT candidatos encontrados"
echo ""

if [ "$MAX_LEVEL" -lt 2 ]; then
    echo "[*] Nivel máximo alcanzado (1). Revisa findings/xss/nivel1-results.txt"
    exit 0
fi

# ════════════════════════════════════════
# NIVEL 2 — WAF bypass payloads
# ════════════════════════════════════════
echo "══════════════════════════════════════════"
echo " Nivel 2 — WAF evasion payloads"
echo "══════════════════════════════════════════"

DALFOX_WAF_FLAG=""
if [ -n "$WAF_DETECTED" ]; then
    echo "    WAF: $WAF_DETECTED — activando evasion"
    DALFOX_WAF_FLAG="--waf-evasion"
fi

dalfox file "$URLS_FILE" \
    --silence \
    --no-color \
    --user-agent "$UA" \
    --delay 200 \
    --timeout 10 \
    --only-poc r \
    $DALFOX_WAF_FLAG \
    $DALFOX_CUSTOM \
    --deep-domxss \
    -o "$RUN_PATH/findings/xss/nivel2-results.txt" \
    2>/dev/null || true

N2_COUNT=$(wc -l < "$RUN_PATH/findings/xss/nivel2-results.txt" 2>/dev/null || echo 0)
echo "    -> $N2_COUNT candidatos encontrados"
echo ""

if [ "$MAX_LEVEL" -lt 3 ]; then
    echo "[*] Nivel máximo alcanzado (2). Revisa findings/xss/"
    exit 0
fi

# ════════════════════════════════════════
# NIVEL 3 — qsreplace análisis de reflexión
# ════════════════════════════════════════
echo "══════════════════════════════════════════"
echo " Nivel 3 — qsreplace análisis de reflexión"
echo "══════════════════════════════════════════"

REFLECT_DIR="$RUN_PATH/findings/xss/reflection-analysis"
mkdir -p "$REFLECT_DIR"

# Si hay payload custom, probarlo directamente con qsreplace
if [ -n "$CUSTOM_PAYLOAD" ]; then
    echo "[*] Probando payload custom en todas las URLs..."
    cat "$URLS_FILE" | qsreplace "$CUSTOM_PAYLOAD" 2>/dev/null \
        | while read -r url; do
            BODY=$(curl -s -A "$UA" -H "X-Bug-Bounty: ${HANDLE}" --max-time 10 "$url" 2>/dev/null || true)
            if echo "$BODY" | grep -qF "$CUSTOM_PAYLOAD" 2>/dev/null; then
                echo "[REFLECTS CUSTOM] $url"
            fi
        done > "$REFLECT_DIR/reflects-custom-payload.txt" 2>/dev/null || true
    CCOUNT=$(wc -l < "$REFLECT_DIR/reflects-custom-payload.txt" 2>/dev/null || echo 0)
    echo "    -> $CCOUNT URLs reflejan el payload custom"
    echo ""
fi

echo "[*] Probando qué caracteres se reflejan..."

# Probar cada carácter peligroso por separado
for CHAR_NAME in "lt:<" "gt:>" "quote:\"" "apos:'" "paren:()" "slash:/" "amp:&"; do
    NAME="${CHAR_NAME%%:*}"
    CHAR="${CHAR_NAME#*:}"
    MARKER="VIGIATEST${NAME}VIGIA"

    cat "$URLS_FILE" | qsreplace "${MARKER}${CHAR}${MARKER}" 2>/dev/null \
        | while read -r url; do
            BODY=$(curl -s -A "$UA" -H "X-Bug-Bounty: ${HANDLE}" --max-time 10 "$url" 2>/dev/null || true)
            if echo "$BODY" | grep -q "${MARKER}${CHAR}${MARKER}" 2>/dev/null; then
                echo "[REFLECTS $NAME] $url"
            fi
        done > "$REFLECT_DIR/reflects-${NAME}.txt" 2>/dev/null || true

    COUNT=$(wc -l < "$REFLECT_DIR/reflects-${NAME}.txt" 2>/dev/null || echo 0)
    [ "$COUNT" -gt 0 ] && echo "    $CHAR ($NAME): $COUNT URLs reflejan"
done

echo ""

# ════════════════════════════════════════
# Resumen
# ════════════════════════════════════════
echo "============================================"
echo " XSS Scan complete"
echo "============================================"
echo ""
echo " Nivel 1 (default):     $N1_COUNT candidatos"
echo " Nivel 2 (WAF bypass):  $N2_COUNT candidatos"
echo " Nivel 3 (reflexión):   ver findings/xss/reflection-analysis/"
if [ -n "$WAF_DETECTED" ]; then
echo " WAF detectado:         $WAF_DETECTED"
fi
echo ""
echo " Output: $RUN_PATH/findings/xss/"
echo ""
echo " Next: Mimir analiza los candidatos con el navegador"
echo "       → contexto de reflexión → payload real → impacto"
echo "============================================"
