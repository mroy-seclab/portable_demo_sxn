#!/usr/bin/env bash
set -euo pipefail

slot="${1:-}"
proto="${2:-}"
ip="${3:-}"
port="${4:-}"

if [[ -z "${slot}" || -z "${proto}" || -z "${ip}" || -z "${port}" ]]; then
  echo "[UC_DOCKER] Usage: $0 <slot> <proto> <ip> <port>" >&2
  exit 1
fi

ip_tag="${ip//./_}"
cname="uc_${proto}_${ip_tag}_${port}"

echo "[UC_DOCKER] Service use case: slot=${slot} proto=${proto} peer=${ip}:${port}"

case "${port}" in
  443)
    echo "[UC_DOCKER] → Backend HTTPS (nginx) sur port 443 via Docker (network=host)"
    docker rm -f "${cname}" >/dev/null 2>&1 || true

    docker run -d \
      --name "${cname}" \
      --network host \
      nginx:alpine >/dev/null
    ;;

  80)
    echo "[UC_DOCKER] → Backend HTTP (nginx) sur port 80 via Docker (network=host)"
    docker rm -f "${cname}" >/dev/null 2>&1 || true

    docker run -d \
      --name "${cname}" \
      --network host \
      nginx:alpine >/dev/null
    ;;

  *)
    echo "[UC_DOCKER] Aucun mapping Docker automatique pour proto=${proto}, port=${port}, on ignore."
    ;;
esac