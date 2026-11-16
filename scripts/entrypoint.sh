#!/usr/bin/env bash
# VIGÍA entrypoint — routes to the right script
#
# Usage:
#   docker compose run --rm recon /scope/target.txt          → recon.sh (Fase 2)
#   docker compose run --rm recon xss /data/target/latest    → xss-scan.sh (Fase 4)
#   docker compose run --rm recon xss /data/target/latest 1  → xss-scan.sh nivel 1 only
#   docker compose run --rm recon wcvs /data/target/latest 20 OK  → wcvs-scan.sh (caché/WCD, ACTIVO, con OK)

case "${1:-}" in
    xss)
        shift
        exec /app/scripts/xss-scan.sh "$@"
        ;;
    wcvs)
        shift
        exec /app/scripts/wcvs-scan.sh "$@"
        ;;
    /scope/*)
        exec /app/scripts/recon.sh "$@"
        ;;
    /app/scripts/*)
        exec "$@"
        ;;
    *)
        exec /app/scripts/recon.sh "$@"
        ;;
esac
