#!/usr/bin/env bash
# Vigía — Web Cache Deception / poisoning con Web-Cache-Vulnerability-Scanner (Hackmanit).
#
# Es ACTIVO: manda peticiones de prueba al target. Solo se lanza A MANO, con el OK de Manu,
# sobre los hosts que el mapa de caché (findings/cache-map.json) marca con señal WCD ALTA/MEDIA.
#
# Uso:
#   docker compose run --rm recon wcvs /data/<programa>/latest <rpm> OK [deception|poisoning] [url ...]
#     <rpm>       peticiones/minuto del programa (p.ej. 20)
#     OK          confirmación explícita (sin ella no se lanza nada)
#     deception   (por defecto) solo las 3 técnicas de WCD
#     poisoning   añade cabeceras/parámetros/cookies/fat GET/encoding (NUNCA dos ni smuggling)
#     url ...     opcional: URLs concretas; si no, la raíz de cada host con señal ALTA/MEDIA
set -euo pipefail

RUN="${1:-}"; RPM="${2:-}"; CONFIRM="${3:-}"; MODE="${4:-deception}"
shift $(( $# >= 4 ? 4 : $# )) || true
if [[ -z "$RUN" || -z "$RPM" ]]; then
  sed -n '2,14p' "$0"; exit 0
fi
[[ -d "$RUN" ]] || { echo "[!] no existe $RUN" >&2; exit 1; }
if [[ "$CONFIRM" != "OK" ]]; then
  echo "[!] Escaneo ACTIVO de caché: falta la confirmación. Añade OK como tercer argumento cuando Manu lo apruebe."
  exit 1
fi
case "$MODE" in
  deception) TESTS="deception" ;;
  poisoning) TESTS="deception,headers,parameters,cookies,fatget,encoding,css,forwarding,cloaking,splitting,pollution" ;;
  *) echo "[!] modo desconocido: $MODE (deception|poisoning)"; exit 1 ;;
esac

HANDLE="${HANDLE:-researcher}"
UA="bugbounty-${HANDLE}"; [[ -n "${UA_OVERRIDE:-}" ]] && UA="${UA_OVERRIDE}"
IDENT_HEADER="${IDENT_HEADER:-X-Bug-Bounty}"
# peticiones/segundo = rpm/60 (WCVS acepta decimales); 1 hilo siempre
RPS=$(python3 -c "print(max(round(${RPM}/60, 3), 0.05))")

OUT="$RUN/findings/wcvs/$(date -u +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
printf 'User-Agent: %s\n%s: %s\n' "$UA" "$IDENT_HEADER" "$HANDLE" > "$OUT/headers.txt"

if [[ $# -gt 0 ]]; then
  printf '%s\n' "$@" > "$OUT/urls.txt"
else
  python3 - "$RUN" > "$OUT/urls.txt" <<'EOF'
import json, sys
from pathlib import Path
run = Path(sys.argv[1])
cm = run / "findings" / "cache-map.json"
if not cm.exists():
    sys.exit(0)
for h, v in json.loads(cm.read_text()).items():
    if str(v.get("wcd_signal", "")).startswith(("ALTA", "MEDIA")):
        print(f"https://{h}/")
EOF
fi
N=$(grep -c . "$OUT/urls.txt" || true)
if [[ "$N" -eq 0 ]]; then
  echo "[!] Ninguna URL: el mapa de caché no marca hosts ALTA/MEDIA (o no existe). Pasa URLs a mano."; exit 0
fi

echo "[*] WCVS · modo ${MODE} (${TESTS}) · ${N} URL(s) · ${RPM}/min (${RPS} req/s) · 1 hilo"
echo "[*] Identificación: User-Agent=\"${UA}\"  ${IDENT_HEADER}=${HANDLE}"
echo "[*] Salida: $OUT"
Web-Cache-Vulnerability-Scanner \
  -u "file:$OUT/urls.txt" \
  -sh "file:$OUT/headers.txt" \
  -onlytest "$TESTS" \
  -t 1 -rr "$RPS" \
  -nc -ns -gr -gl -gp "$OUT/" 2>&1 | tee "$OUT/wcvs.log" || true
echo
echo "[+] Hecho. Informe: $OUT  — son PISTAS: un WCD de verdad se confirma a mano con nuestras dos cuentas (página con sesión cacheada)."
