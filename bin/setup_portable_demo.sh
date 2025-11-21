#!/usr/bin/env bash
set -euo pipefail

########################################
# 0. Usage & parsing des options
########################################

usage() {
  cat <<EOF
Usage: $0 -c <config.env> [-m <mode>]

  -c  Fichier de configuration (ex: config/sxn_lab.env)
  -m  Mode d'exécution :
        all      : config SXN (A puis B) + stack Docker (défaut)
        sxn      : seulement configuration SXN (A puis B)
        dockers  : seulement stack Docker

Exemples :
  $0 -c config/sxn_lab.env
  $0 -c config/sxn_lab.env -m sxn
  $0 -c config/sxn_lab.env -m dockers
EOF
  exit 1
}

MODE="all"
CONFIG_FILE=""

while getopts ":c:m:h" opt; do
  case "$opt" in
    c) CONFIG_FILE="$OPTARG" ;;
    m) MODE="$OPTARG" ;;
    h|*) usage ;;
  esac
done

case "${MODE}" in
  all|sxn|dockers) ;;
  *)
    echo "[ERREUR] Mode inconnu: ${MODE}" >&2
    usage
    ;;
esac

if [[ -z "${CONFIG_FILE}" ]]; then
  echo "[ERREUR] Aucun fichier de config fourni."
  usage
fi

if [[ ! -f "${CONFIG_FILE}" ]]; then
  echo "[ERREUR] Fichier de config introuvable: ${CONFIG_FILE}" >&2
  exit 1
fi

########################################
# 1. Dossiers, scripts, logging
########################################

# Répertoire du script (bin)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Racine du projet = parent de bin
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

LIB_DIR="${ROOT_DIR}/lib"

# shellcheck disable=SC1091
source "${LIB_DIR}/common.sh"

DOCKER_SCRIPT="${ROOT_DIR}/dockers/base_SXN/setup_dockers_base_sxn.sh"
TIO_SCRIPT="${ROOT_DIR}/tio/setup_tio_base_sxn.sh"
BASE_LUA_DIR="${ROOT_DIR}/tio/base_SXN"
DETECT_LUA="${BASE_LUA_DIR}/detect_gate.lua"
INTERLINK_LUA="${BASE_LUA_DIR}/interlink_ntp.lua"

if [[ ! -x "${DOCKER_SCRIPT}" ]]; then
  echo "[ERREUR] Script Docker introuvable ou non exécutable: ${DOCKER_SCRIPT}" >&2
  exit 1
fi

if [[ ! -x "${TIO_SCRIPT}" ]]; then
  echo "[ERREUR] Script tio introuvable ou non exécutable: ${TIO_SCRIPT}" >&2
  exit 1
fi

mkdir -p "${BASE_LUA_DIR}"

LOG_DIR="${ROOT_DIR}/logs"
mkdir -p "${LOG_DIR}"
LOG_FILE="${LOG_DIR}/portable_demo_$(date +%Y%m%d_%H%M%S).log"

########################################
# 2. Chargement config & variables globales
########################################

# shellcheck disable=SC1090
source "${CONFIG_FILE}"

# IP du syslog docker (celle à comparer pour savoir si on fait TLS+PKI)
: "${DOCKER_SYSLOG_IP:=192.168.2.2}"

# Valeurs globales (peuvent être écrasées par profil par défaut ou interactif)
: "${SYSLOG_SERVER:=192.168.2.2}"

# Port vu par le SXN pour le remote syslog (valeur par défaut, surchargée par gate)
: "${SYSLOG_PORT:=6514}"

# Port d’écoute du syslog-ng dans les dockers (host) – global pour la stack
: "${SYSLOG_LISTEN_PORT:=${SYSLOG_PORT}}"

# Créds SXN (par défaut, override par .env puis prompts)
: "${SXN_ADMIN_USER:=admin}"
: "${SXN_ADMIN_PASSWORD:=SeclabFR2011!}"

: "${SYSLOG_IFACE:=eno1}"

: "${NTP_ENABLE:=1}"
: "${NTP_SERVER:=${SYSLOG_SERVER}}"
: "${NTP_IFACE:=${SYSLOG_IFACE}}"
: "${NTP_SERVER2:=}"
: "${NTP_IFACE2:=}"

# SNMP global (agent + traps)
: "${SNMP_ENABLE:=1}"
: "${SNMP_IFACE:=${SYSLOG_IFACE}}"

: "${SNMP_USER:=user}"
: "${SNMP_AUTH_PASS:=Password1}"
: "${SNMP_PRIV_PASS:=${SNMP_AUTH_PASS}}"

: "${SNMPD_PORT:=161}"
: "${SNMP_TRAP_REMOTE_IP:=${SNMPTRAPS_SERVER:-${SYSLOG_SERVER}}}"
: "${SNMP_TRAP_REMOTE_PORT:=162}"

# Activation syslog côté SXN (par défaut, mais sera géré par gate)
: "${SYSLOG_ENABLE:=1}"

: "${P12_PASSWORD:=seclab}"
: "${SYSLOG_SAN_DNS:=server.syslog.local}"

: "${CERT_BASE_DIR:=${ROOT_DIR}/dockers/base_SXN/syslog-ng/cert}"

# IPs par interface pour chaque gate (remplies à partir du .env)
GATE_ENO0_IP=""
GATE_ENO1_IP=""

# Runtimes NTP pour savoir si interlink est pertinent
RUNTIME_NTP_ENABLE_A=""
RUNTIME_NTP_ENABLE_B=""

# Mapping ports ↔ gates
DEV_A=""
DEV_B=""

##############################################
# 2bis. Prompts pour choisir les creds SXN (global)
##############################################

prompt_runtime_params() {
  echo
  echo "=== Configuration des paramètres SXN (global) ==="
  echo "(Entrée = valeurs par défaut du .env)"

  local input

  # ----------- User SXN -----------
  read -rp "Nom d'utilisateur SXN [${SXN_ADMIN_USER}] : " input
  if [[ -n "$input" ]]; then
    SXN_ADMIN_USER="$input"
  fi

  # ----------- Password SXN -----------
  read -rsp "Mot de passe SXN [${SXN_ADMIN_PASSWORD}] : " input
  echo
  if [[ -n "$input" ]]; then
    SXN_ADMIN_PASSWORD="$input"
  fi

  export SXN_ADMIN_USER
  export SXN_ADMIN_PASSWORD

  echo
  echo "[OK] Paramètres globaux SXN :"
  echo "  → User SXN             : ${SXN_ADMIN_USER}"
  echo "  → Password SXN         : (caché)"
  echo
  sleep 1
}

########################################
# 3. Détection des gates via tio
########################################

list_serial_ports() {
  PORT_LINES=()
  while IFS= read -r line; do
    PORT_LINES+=("$line")
  done < <(tio -l 2>/dev/null | awk '/^\/dev\// {print}')

  if ((${#PORT_LINES[@]} == 0)); then
    echo "[ERREUR] Aucun port série détecté via 'tio -l'." >&2
    exit 1
  fi

  echo "Ports série disponibles :"
  local i
  for i in "${!PORT_LINES[@]}"; do
    printf "  %d) %s\n" "$((i+1))" "${PORT_LINES[$i]}"
  done
  echo
}

select_port() {
  local prompt="$1"
  local choice idx

  while true; do
    read -rp "${prompt}" choice
    if [[ ! "${choice}" =~ ^[0-9]+$ ]]; then
      echo "Merci d'entrer un numéro valide."
      continue
    fi
    idx=$((choice-1))
    if (( idx < 0 || idx >= ${#PORT_LINES[@]} )); then
      echo "Numéro en dehors de la liste."
      continue
    fi
    echo "${PORT_LINES[$idx]%% *}"
    return 0
  done
}

ensure_detect_lua() {
  cat > "${DETECT_LUA}" <<'EOF'
-- detect_gate.lua : utilisé par l'orchestrateur pour lire le prompt
-- et en déduire la gate (A/B/…).

msleep(500)
write("\n")

local gate = nil

local patterns = {
  "Sec.*login:",
  "Sec.*>"
}

for i = 1, #patterns do
  local rc, match = expect(patterns[i], 5000)
  if rc == 1 and type(match) == "string" then
    local g = match:match("Sec[%w%-]*%-([A-Z])")
    if g then
      gate = g
      break
    end
  end
end

if gate then
  print("GATE=" .. gate)
else
  print("GATE=?")
end

exit(0)
EOF
}

detect_gate_for_device() {
  local dev="$1"
  ensure_detect_lua

  echo "[INFO] Détection de la gate sur ${dev} ..." >&2

  local out gate
  out=$(tio --script-file "${DETECT_LUA}" "${dev}" 2>&1 || true)

  {
    echo "==== detect_gate_for_device(${dev}) ===="
    printf '%s\n' "$out"
    echo "========================================"
  } >> "${LOG_FILE}"

  gate=$(printf '%s\n' "$out" \
    | sed -n 's/.*GATE=\([A-Z]\).*/\1/p' \
    | head -n1)

  if [[ -z "${gate}" || "${gate}" == "?" ]]; then
    echo "[WARN] Impossible de déduire la gate sur ${dev}." >&2
    return 1
  fi

  echo "  → ${dev} ↔ gate ${gate}" >&2
  printf '%s\n' "${gate}"
}

discover_gates() {
  echo "=== Découverte des SXN connectés (gates) ==="
  list_serial_ports

  echo "Sélectionne les ports correspondant aux SXN A et B."
  local dev1 dev2 gate1 gate2

  dev1=$(select_port "Port pour le premier SXN (numéro) : ")
  dev2=$(select_port "Port pour le second SXN (numéro) : ")

  echo

  gate1=$(detect_gate_for_device "${dev1}") || {
    echo "[ERREUR] Échec de détection de la gate sur ${dev1}" >&2
    exit 1
  }

  echo

  gate2=$(detect_gate_for_device "${dev2}") || {
    echo "[ERREUR] Échec de détection de la gate sur ${dev2}" >&2
    exit 1
  }

  echo
  echo "=== Mapping détecté ==="
  echo "  ${dev1} ↔ gate ${gate1}"
  echo "  ${dev2} ↔ gate ${gate2}"
  echo

  if [[ "${gate1}" == "A" ]]; then DEV_A="${dev1}"; fi
  if [[ "${gate2}" == "A" ]]; then DEV_A="${dev2}"; fi
  if [[ "${gate1}" == "B" ]]; then DEV_B="${dev1}"; fi
  if [[ "${gate2}" == "B" ]]; then DEV_B="${dev2}"; fi

  if [[ -z "${DEV_A}" || -z "${DEV_B}" ]]; then
    echo "[WARN] Impossible d'identifier clairement les deux gates A et B."
    echo "       DEV_A=${DEV_A:-<none>}, DEV_B=${DEV_B:-<none>}"
  fi
}

########################################
# 4. Profils par défaut par gate (A/B)
########################################

load_gate_defaults_for_current_gate() {
  case "${GATE}" in
    A)
      [[ -n "${GATE_A_ENO0_IP:-}" ]] && GATE_ENO0_IP="${GATE_A_ENO0_IP}"
      [[ -n "${GATE_A_ENO1_IP:-}" ]] && GATE_ENO1_IP="${GATE_A_ENO1_IP}"

      [[ -n "${GATE_A_SYSLOG_IFACE:-}" ]] && SYSLOG_IFACE="${GATE_A_SYSLOG_IFACE}"
      [[ -n "${GATE_A_SYSLOG_SERVER:-}" ]] && SYSLOG_SERVER="${GATE_A_SYSLOG_SERVER}"
      [[ -n "${GATE_A_SYSLOG_PORT:-}" ]] && SYSLOG_PORT="${GATE_A_SYSLOG_PORT}"
      [[ -n "${GATE_A_SYSLOG_ENABLE:-}" ]] && SYSLOG_ENABLE="${GATE_A_SYSLOG_ENABLE}"

      [[ -n "${GATE_A_NTP_ENABLE:-}" ]] && NTP_ENABLE="${GATE_A_NTP_ENABLE}"
      [[ -n "${GATE_A_NTP_IFACE:-}" ]] && NTP_IFACE="${GATE_A_NTP_IFACE}"
      [[ -n "${GATE_A_NTP_SERVER:-}" ]] && NTP_SERVER="${GATE_A_NTP_SERVER}"
      [[ -n "${GATE_A_NTP_IFACE2:-}" ]] && NTP_IFACE2="${GATE_A_NTP_IFACE2}"
      [[ -n "${GATE_A_NTP_SERVER2:-}" ]] && NTP_SERVER2="${GATE_A_NTP_SERVER2}"
            # SNMP
      [[ -n "${GATE_A_SNMP_ENABLE:-}" ]] && SNMP_ENABLE="${GATE_A_SNMP_ENABLE}"
      [[ -n "${GATE_A_SNMP_IFACE:-}" ]] && SNMP_IFACE="${GATE_A_SNMP_IFACE}"
      [[ -n "${GATE_A_SNMP_USER:-}" ]] && SNMP_USER="${GATE_A_SNMP_USER}"
      [[ -n "${GATE_A_SNMP_AUTH_PASS:-}" ]] && SNMP_AUTH_PASS="${GATE_A_SNMP_AUTH_PASS}"
      [[ -n "${GATE_A_SNMP_PRIV_PASS:-}" ]] && SNMP_PRIV_PASS="${GATE_A_SNMP_PRIV_PASS}"
      [[ -n "${GATE_A_SNMPD_PORT:-}" ]] && SNMPD_PORT="${GATE_A_SNMPD_PORT}"
      [[ -n "${GATE_A_SNMP_TRAP_REMOTE_PORT:-}" ]] && SNMP_TRAP_REMOTE_PORT="${GATE_A_SNMP_TRAP_REMOTE_PORT}"

      ;;
    B)
      [[ -n "${GATE_B_ENO0_IP:-}" ]] && GATE_ENO0_IP="${GATE_B_ENO0_IP}"
      [[ -n "${GATE_B_ENO1_IP:-}" ]] && GATE_ENO1_IP="${GATE_B_ENO1_IP}"

      [[ -n "${GATE_B_SYSLOG_IFACE:-}" ]] && SYSLOG_IFACE="${GATE_B_SYSLOG_IFACE}"
      [[ -n "${GATE_B_SYSLOG_SERVER:-}" ]] && SYSLOG_SERVER="${GATE_B_SYSLOG_SERVER}"
      [[ -n "${GATE_B_SYSLOG_PORT:-}" ]] && SYSLOG_PORT="${GATE_B_SYSLOG_PORT}"
      [[ -n "${GATE_B_SYSLOG_ENABLE:-}" ]] && SYSLOG_ENABLE="${GATE_B_SYSLOG_ENABLE}"

      [[ -n "${GATE_B_NTP_ENABLE:-}" ]] && NTP_ENABLE="${GATE_B_NTP_ENABLE}"
      [[ -n "${GATE_B_NTP_IFACE:-}" ]] && NTP_IFACE="${GATE_B_NTP_IFACE}"
      [[ -n "${GATE_B_NTP_SERVER:-}" ]] && NTP_SERVER="${GATE_B_NTP_SERVER}"
      [[ -n "${GATE_B_NTP_IFACE2:-}" ]] && NTP_IFACE2="${GATE_B_NTP_IFACE2}"
      [[ -n "${GATE_B_NTP_SERVER2:-}" ]] && NTP_SERVER2="${GATE_B_NTP_SERVER2}"

      [[ -n "${GATE_B_SNMP_ENABLE:-}" ]] && SNMP_ENABLE="${GATE_B_SNMP_ENABLE}"
      [[ -n "${GATE_B_SNMP_IFACE:-}" ]] && SNMP_IFACE="${GATE_B_SNMP_IFACE}"
      [[ -n "${GATE_B_SNMP_USER:-}" ]] && SNMP_USER="${GATE_B_SNMP_USER}"
      [[ -n "${GATE_B_SNMP_AUTH_PASS:-}" ]] && SNMP_AUTH_PASS="${GATE_B_SNMP_AUTH_PASS}"
      [[ -n "${GATE_B_SNMP_PRIV_PASS:-}" ]] && SNMP_PRIV_PASS="${GATE_B_SNMP_PRIV_PASS}"
      [[ -n "${GATE_B_SNMPD_PORT:-}" ]] && SNMPD_PORT="${GATE_B_SNMPD_PORT}"
      [[ -n "${GATE_B_SNMP_TRAP_REMOTE_PORT:-}" ]] && SNMP_TRAP_REMOTE_PORT="${GATE_B_SNMP_TRAP_REMOTE_PORT}"

      ;;
    *)
      echo "[WARN] Aucune valeur par défaut trouvée pour GATE=${GATE}"
      ;;
  esac
}

maybe_apply_defaults_for_gate() {
  echo "=== Profils par défaut pour gate ${GATE} ==="
  echo "S'il y a des valeurs définies dans le .env (GATE_${GATE}_*),"
  echo "elles peuvent être appliquées automatiquement."

  local answer
  read -rp "→ Appliquer les valeurs par défaut du .env pour gate ${GATE} ? [Y/n] : " answer
  case "${answer}" in
    n|N)
      echo "  → On passe en mode configuration interactive."
      return 1
      ;;
    *)
      load_gate_defaults_for_current_gate
      echo "  → Valeurs par défaut appliquées pour gate ${GATE}:"
      echo "    eno0 IP   : ${GATE_ENO0_IP:-<none>}"
      echo "    eno1 IP   : ${GATE_ENO1_IP:-<none>}"
      echo "    syslog IF : ${SYSLOG_IFACE}"
      echo "    syslog IP : ${SYSLOG_SERVER}"
      echo "    syslog P  : ${SYSLOG_PORT}"
      echo "    syslog en : ${SYSLOG_ENABLE}"
      echo "    NTP en    : ${NTP_ENABLE}"
      echo "    NTP IF    : ${NTP_IFACE:-<none>}"
      echo "    NTP srv   : ${NTP_SERVER:-<none>}"
      echo "    NTP IF2   : ${NTP_IFACE2:-<none>}"
      echo "    NTP srv2  : ${NTP_SERVER2:-<none>}"
      echo "  ───────────── SNMP ─────────────"
      echo "   SNMP_ENABLE        : ${SNMP_ENABLE}"
      echo "   SNMP_IFACE         : ${SNMP_IFACE}"
      echo "   SNMP_USER          : ${SNMP_USER}"
      echo "   SNMP_AUTH_PASS     : ${SNMP_AUTH_PASS}"
      echo "   SNMP_PRIV_PASS     : ${SNMP_PRIV_PASS}"
      echo "   SNMPD_PORT         : ${SNMPD_PORT}"
      echo "   SNMP_TRAP_IP       : ${SNMP_TRAP_REMOTE_IP}"
      echo "   SNMP_TRAP_PORT     : ${SNMP_TRAP_REMOTE_PORT}"
      echo
      echo
      return 0
      ;;
  esac
}

########################################
# 5. Config IP d'une interface via tio
########################################

configure_interface_lua() {
  local ifname="$1"
  local ipaddr="$2"
  local device="$3"
  local lua_file="${BASE_LUA_DIR}/config_iface_${GATE}_${ifname}.lua"

  cat > "${lua_file}" <<EOF
-- SCRIPT : config_iface_${GATE}_${ifname}.lua
-- Objet : configurer l'IP de ${ifname} dans la config 1

local GATE = "${GATE}"
local CONFIG_ID = 1

local ADMIN_USER = "${SXN_ADMIN_USER}"
local ADMIN_PASS = "${SXN_ADMIN_PASSWORD}"

local IP_ADDRESS = "${ipaddr}"
local INTERFACE = "${ifname}"

local SYSTEM_PROMPT = "SecOS-" .. GATE .. ">"
local CONFIG_PROMPT = "SecOS-" .. GATE .. " \\\(config\\\)>"

msleep(500)
write("\\n")

local rc = expect("login:", 1000)

if rc == 1 then
  write(ADMIN_USER .. "\\n")
  expect("Password:", 5000)
  write(ADMIN_PASS .. "\\n")
  expect(SYSTEM_PROMPT)
else
  write("\\n")
  expect(SYSTEM_PROMPT)
end

write("config edit " .. CONFIG_ID .. "\\n")
expect(CONFIG_PROMPT)

write("net set addr " .. IP_ADDRESS .. " iface " .. INTERFACE .. "\\n")
expect(CONFIG_PROMPT)

write("exit\\n")
expect(SYSTEM_PROMPT)

write("config save " .. CONFIG_ID .. "\\n")
expect(SYSTEM_PROMPT)

exit(0)
EOF

  echo "  → Configuration IP ${ifname}=${ipaddr} sur gate ${GATE}"
  local out
  out=$(tio --script-file "${lua_file}" "${device}" 2>&1 || true)
  {
    echo "==== configure_interface(${device}, ${ifname}, ${ipaddr}) ===="
    printf '%s\n' "$out"
    echo "=============================================================="
  } >> "${LOG_FILE}"
}

########################################
# 6. Interactif pour IP & NTP/syslog
########################################

interactive_interface_config() {
  local device="$1"
  echo "=== Configuration IP des interfaces SXN pour la gate ${GATE} (${device}) ==="

  local answer first_if ip other_if ip2

  read -rp "  Interface à configurer en premier (eno0/eno1) [${SYSLOG_IFACE}] : " answer
  if [[ -n "${answer}" ]]; then
    first_if="${answer}"
  else
    first_if="${SYSLOG_IFACE}"
  fi

  read -rp "  IP/mask pour ${first_if} (ex 192.168.2.1/24) [${SXN_IFACE_IP:-192.168.2.1/24}] : " answer
  if [[ -n "${answer}" ]]; then
    ip="${answer}"
  else
    ip="${SXN_IFACE_IP:-192.168.2.1/24}"
  fi

  SXN_IFACE="${first_if}"
  SXN_IFACE_IP="${ip}"
  configure_interface_lua "${SXN_IFACE}" "${SXN_IFACE_IP}" "${device}"

  if [[ "${first_if}" == "eno0" ]]; then
    other_if="eno1"
  else
    other_if="eno0"
  fi

  read -rp "  Configurer aussi une IP sur ${other_if} ? [y/N] : " answer
  case "${answer}" in
    y|Y|o|O)
      read -rp "  IP/mask pour ${other_if} (ex 192.168.3.1/24) : " ip2
      if [[ -n "${ip2}" ]]; then
        configure_interface_lua "${other_if}" "${ip2}" "${device}"
        if [[ "${other_if}" == "eno0" ]]; then
          GATE_ENO0_IP="${ip2}"
        else
          GATE_ENO1_IP="${ip2}"
        fi
      fi
      ;;
    *)
      echo "  → ${other_if} laissé non configuré."
      ;;
  esac

  echo
}

interactive_network_params() {
  echo "=== Paramètres NTP / Syslog pour la gate ${GATE} ==="

  local answer

  read -rp "  Interface SXN pour syslog/snmptraps (eno0/eno1) [${SYSLOG_IFACE}] : " answer
  if [[ -n "${answer}" ]]; then
    SYSLOG_IFACE="${answer}"
  fi

  read -rp "  IP du serveur (syslog/snmptraps) [${SYSLOG_SERVER}] : " answer
  if [[ -n "${answer}" ]]; then
    SYSLOG_SERVER="${answer}"
  fi
  
  SNMPTRAPS_SERVER="${SYSLOG_SERVER}"

  read -rp "  Port syslog TLS pour cette gate (doit matcher le port écouté par le serveur) [${SYSLOG_PORT}] : " answer
  if [[ -n "${answer}" ]]; then
    SYSLOG_PORT="${answer}"
  fi

  echo
  read -rp "  Configurer NTP sur cette gate ? [y/N] : " answer
  case "${answer}" in
    y|Y|o|O)
      NTP_ENABLE=1

      read -rp "    Interface NTP principale (eno0/eno1) [${NTP_IFACE:-${SYSLOG_IFACE}}] : " answer
      if [[ -n "${answer}" ]]; then
        NTP_IFACE="${answer}"
      else
        NTP_IFACE="${NTP_IFACE:-${SYSLOG_IFACE}}"
      fi

      read -rp "    IP du serveur NTP [${NTP_SERVER:-${SYSLOG_SERVER}}] : " answer
      if [[ -n "${answer}" ]]; then
        NTP_SERVER="${answer}"
      else
        NTP_SERVER="${NTP_SERVER:-${SYSLOG_SERVER}}"
      fi

      echo
      read -rp "    Configurer un 2ᵉ serveur/interface NTP ? [y/N] : " answer
      case "${answer}" in
        y|Y|o|O)
          local other_if
          if [[ "${NTP_IFACE}" == "eno0" ]]; then
            other_if="eno1"
          else
            other_if="eno0"
          fi

          read -rp "      2ᵉ interface NTP (eno0/eno1) [${other_if}] : " answer
          if [[ -n "${answer}" ]]; then
            NTP_IFACE2="${answer}"
          else
            NTP_IFACE2="${other_if}"
          fi

          read -rp "      IP du 2ᵉ serveur NTP [${NTP_SERVER}] : " answer
          if [[ -n "${answer}" ]]; then
            NTP_SERVER2="${answer}"
          else
            NTP_SERVER2="${NTP_SERVER}"
          fi
          ;;
        *)
          NTP_IFACE2=""
          NTP_SERVER2=""
          ;;
      esac
      ;;
    *)
      NTP_ENABLE=0
      NTP_IFACE=""
      NTP_SERVER=""
      NTP_IFACE2=""
      NTP_SERVER2=""
      ;;
  esac

  echo
  read -rp "  Configurer SNMP (agent + traps) sur cette gate ? [y/N] : " answer
  case "${answer}" in
    y|Y|o|O)
      SNMP_ENABLE=1

      read -rp "    Interface SNMP (eno0/eno1) [${SNMP_IFACE:-${SYSLOG_IFACE}}] : " answer
      if [[ -n "${answer}" ]]; then
        SNMP_IFACE="${answer}"
      else
        SNMP_IFACE="${SNMP_IFACE:-${SYSLOG_IFACE}}"
      fi

      read -rp "    User SNMPv3 [${SNMP_USER}] : " answer
      if [[ -n "${answer}" ]]; then
        SNMP_USER="${answer}"
      fi

      # Auth passphrase
      read -rsp "    Passphrase d'authentification SNMP (8-16 chars) [${SNMP_AUTH_PASS}] : " answer
      echo
      if [[ -n "${answer}" ]]; then
        SNMP_AUTH_PASS="${answer}"
      fi

      # Privacy passphrase
      read -rsp "    Passphrase de chiffrement SNMP (8-16 chars) [${SNMP_PRIV_PASS}] : " answer
      echo
      if [[ -n "${answer}" ]]; then
        SNMP_PRIV_PASS="${answer}"
      fi

      read -rp "    Port snmpd (agent SNMP) [${SNMPD_PORT}] : " answer
      if [[ -n "${answer}" ]]; then
        SNMPD_PORT="${answer}"
      fi

      read -rp "    IP du serveur SNMP traps [${SNMP_TRAP_REMOTE_IP:-${SNMPTRAPS_SERVER:-${SYSLOG_SERVER}}}] : " answer
      if [[ -n "${answer}" ]]; then
        SNMP_TRAP_REMOTE_IP="${answer}"
      else
        SNMP_TRAP_REMOTE_IP="${SNMP_TRAP_REMOTE_IP:-${SNMPTRAPS_SERVER:-${SYSLOG_SERVER}}}"
      fi

      read -rp "    Port SNMP traps [${SNMP_TRAP_REMOTE_PORT}] : " answer
      if [[ -n "${answer}" ]]; then
        SNMP_TRAP_REMOTE_PORT="${answer}"
      fi
      ;;
    *)
      SNMP_ENABLE=0
      SNMP_IFACE=""
      SNMP_USER=""
      SNMP_AUTH_PASS=""
      SNMP_PRIV_PASS=""
      ;;
  esac

  echo
  echo "Récapitulatif gate ${GATE} :"
  echo "  Syslog iface : ${SYSLOG_IFACE}"
  echo "  Syslog IP    : ${SYSLOG_SERVER}"
  echo "  Syslog port  : ${SYSLOG_PORT}"
  echo "  Syslog enable: ${SYSLOG_ENABLE}"
  echo "  NTP enable   : ${NTP_ENABLE}"
  if [[ "${NTP_ENABLE}" != "0" ]]; then
    echo "  NTP server   : ${NTP_SERVER} (${NTP_IFACE})"
    echo "  NTP server2  : ${NTP_SERVER2:-<none>} (${NTP_IFACE2:-<none>})"
  fi
  echo "  SNMP enable  : ${SNMP_ENABLE}"
  if [[ "${SNMP_ENABLE}" != "0" ]]; then
    echo "  SNMP iface   : ${SNMP_IFACE}"
    echo "  SNMP user    : ${SNMP_USER}"
    echo "  SNMPd port   : ${SNMPD_PORT}"
    echo "  SNMP trap IP : ${SNMP_TRAP_REMOTE_IP}"
    echo "  SNMP trap pt : ${SNMP_TRAP_REMOTE_PORT}"
  fi
  echo
}

########################################
# 7. Exécution setup_tio pour une gate
########################################

run_sxn_for_current_gate() {
  local device="$1"

  echo "[SXN] Configuration de la gate ${GATE} sur ${device}..."

  set +e
  {
    cd "${ROOT_DIR}/tio" || exit 1
    export DEVICE="${device}"
    export GATE

    export SXN_IFACE
    export SXN_IFACE_IP

    export SYSLOG_IFACE
    export SYSLOG_SERVER
    export SYSLOG_PORT

    export NTP_ENABLE
    export NTP_IFACE
    export NTP_SERVER
    export NTP_IFACE2
    export NTP_SERVER2

    export CERT_BASE_DIR
    export SNMPTRAPS_SERVER

    export SXN_ADMIN_USER
    export SXN_ADMIN_PASSWORD

    export SNMP_ENABLE
    export SNMP_IFACE
    export SNMP_USER
    export SNMP_AUTH_PASS
    export SNMP_PRIV_PASS
    export SNMPD_PORT
    export SNMP_TRAP_REMOTE_IP
    export SNMP_TRAP_REMOTE_PORT
    # Décision : TLS+PKI seulement si cette gate pointe vers le docker
    local use_docker="0"
    if [[ "${SYSLOG_SERVER}" == "${DOCKER_SYSLOG_IP}" ]]; then
      use_docker="1"
    fi
    export USE_DOCKER_SYSLOG="${use_docker}"

    ./setup_tio_base_sxn.sh
  } >> "${LOG_FILE}" 2>&1
  local rc=$?
  set -e

  if (( rc == 0 )); then
    echo "  → Gate ${GATE} configurée avec succès (détails dans ${LOG_FILE})"

    # Check services visible dans le terminal
    if [[ -f "${BASE_LUA_DIR}/check_services_${GATE}.lua" ]]; then
      echo
      echo "  → Vérification NTP / Syslog sur gate ${GATE} (output ci-dessous) :"
      tio --script-file "${BASE_LUA_DIR}/check_services_${GATE}.lua" "${device}" | tee -a "${LOG_FILE}"
      echo "  → Fin du check services pour gate ${GATE}"
      echo
    fi
  else
    echo "  [WARN] Échec de la configuration de la gate ${GATE} (code=${rc})."
    echo "         Regarde le log pour les détails : ${LOG_FILE}"
  fi
}

########################################
# 8. Interlink NTP (maître/esclave)
########################################

configure_interlink_between_gates() {
  if [[ -z "${DEV_A}" || -z "${DEV_B}" ]]; then
    echo "[INFO] Interlink NTP: impossible (A ou B manquant)."
    return
  fi

  local count_ntp=0
  [[ "${RUNTIME_NTP_ENABLE_A}" == "1" ]] && ((count_ntp++))
  [[ "${RUNTIME_NTP_ENABLE_B}" == "1" ]] && ((count_ntp++))

  if (( count_ntp == 0 )); then
    echo "[INFO] Interlink NTP: aucun des deux SXN n'a NTP activé, rien à faire."
    return
  fi

  if (( count_ntp == 2 )); then
    echo "[INFO] Interlink NTP: les deux gates ont NTP activé, interlink inutile."
    return
  fi

  local master_gate slave_gate slave_dev
  if [[ "${RUNTIME_NTP_ENABLE_A}" == "1" ]]; then
    master_gate="A"
    slave_gate="B"
    slave_dev="${DEV_B}"
  else
    master_gate="B"
    slave_gate="A"
    slave_dev="${DEV_A}"
  fi

  echo
  echo "=== Interlink NTP ==="
  echo "Gate ${master_gate} : NTP direct"
  echo "Gate ${slave_gate}  : peut être configurée en 'clock set sync mode interlink'"
  echo

  if yes_no_default_no "→ Activer 'clock set sync mode interlink' sur la gate ${slave_gate} ?"; then
      mkdir -p "${BASE_LUA_DIR}"
      cat > "${INTERLINK_LUA}" <<EOF
-- interlink_ntp.lua : configurer le mode NTP interlink sur la gate ${slave_gate}

local GATE = "${slave_gate}"
local ADMIN_USER = "${SXN_ADMIN_USER}"
local ADMIN_PASS = "${SXN_ADMIN_PASSWORD}"

local SYSTEM_PROMPT = "SecOS-" .. GATE .. ">"
local CONFIG_PROMPT = "SecOS-" .. GATE .. " \\\(config\\\)>"

msleep(500)
write("\\n")

local rc = expect("login:", 1000)

if rc == 1 then
  write(ADMIN_USER .. "\\n")
  expect("Password:")
  write(ADMIN_PASS .. "\\n")
  expect(SYSTEM_PROMPT)
else
  write("\\n")
  expect(SYSTEM_PROMPT)
end

write("config edit 1\\n")
expect(CONFIG_PROMPT)

write("clock set sync mode interlink\\n")
expect(CONFIG_PROMPT)

write("exit\\n")
expect(SYSTEM_PROMPT)

write("config save 1\\n")
expect(SYSTEM_PROMPT)

write("system reboot\\n")
msleep(1000)
exit(0)
EOF

      echo "[SXN] Interlink NTP sur gate ${slave_gate} (${slave_dev})..."
      local out
      out=$(tio --script-file "${INTERLINK_LUA}" "${slave_dev}" 2>&1 || true)
      {
        echo "==== interlink_ntp(${slave_dev}, gate=${slave_gate}) ===="
        printf '%s\n' "$out"
        echo "========================================================="
      } >> "${LOG_FILE}"
      echo "  → Interlink NTP configuré sur la gate ${slave_gate} (voir log)."
  else
    echo "[INFO] Interlink NTP non configuré."
  fi
}

########################################
# 9. Stack Docker (syslog-ng, ntp, zabbix)
########################################

run_dockers() {
  echo "[DOCKER] Déploiement de la stack syslog-ng / ntp / zabbix-snmptraps..."
  (
    cd "${ROOT_DIR}/dockers/base_SXN"
    export BASE_DIR="${ROOT_DIR}/dockers/base_SXN"
    # IP vue par les SXN comme serveur syslog/ntp
    export SYSLOG_SERVER_IP="${DOCKER_SYSLOG_IP}"
    # Port écouté par syslog-ng côté host (global)
    export SYSLOG_LISTEN_PORT="${SYSLOG_LISTEN_PORT}"
    export SYSLOG_SAN_DNS
    export P12_PASSWORD
    ./setup_dockers_base_sxn.sh
  ) >> "${LOG_FILE}" 2>&1

  echo "  → Stack Docker démarrée (détails dans ${LOG_FILE})"
}

########################################
# 10. Orchestration globale
########################################

main() {
  echo "=== Orchestrateur portable SXN ==="
  echo "Config file : ${CONFIG_FILE}"
  echo "Mode        : ${MODE}"
  echo "Log file    : ${LOG_FILE}"
  echo

  # 0) Prompts globaux (creds SXN)
  prompt_runtime_params

  # 1) Découverte des gates / mapping A/B
  discover_gates

  ####################################
  # 2) Stack Docker (PKI + services)
  ####################################
  case "${MODE}" in
    all|dockers)
      run_dockers
      ;;
    sxn)
      echo "[INFO] Mode 'sxn' : stack Docker non lancée."
      ;;
  esac
  echo

  ####################################
  # 3) Configuration des SXN (A/B)
  ####################################
  if [[ "${MODE}" == "all" || "${MODE}" == "sxn" ]]; then

    # 3.1) Gate A
    if [[ -n "${DEV_A}" ]]; then
      echo "=== Configuration gate A (${DEV_A}) ==="
      GATE="A"
      DEVICE="${DEV_A}"

      if yes_no_default_yes "Configurer la gate A maintenant ?"; then
          if maybe_apply_defaults_for_gate; then
            [[ -n "${GATE_ENO0_IP:-}" ]] && configure_interface_lua "eno0" "${GATE_ENO0_IP}" "${DEVICE}"
            [[ -n "${GATE_ENO1_IP:-}" ]] && configure_interface_lua "eno1" "${GATE_ENO1_IP}" "${DEVICE}"
          else
            interactive_interface_config "${DEVICE}"
            interactive_network_params
          fi

          RUNTIME_NTP_ENABLE_A="${NTP_ENABLE}"
          run_sxn_for_current_gate "${DEVICE}"
      else
          echo "  → Gate A ignorée."
          RUNTIME_NTP_ENABLE_A="0"
      fi
      echo
    fi

    # 3.2) Gate B
    if [[ -n "${DEV_B}" ]]; then
      echo "=== Configuration gate B (${DEV_B}) ==="
      GATE="B"
      DEVICE="${DEV_B}"

      if yes_no_default_yes "Configurer la gate B maintenant ?"; then
          if maybe_apply_defaults_for_gate; then
            [[ -n "${GATE_ENO0_IP:-}" ]] && configure_interface_lua "eno0" "${GATE_ENO0_IP}" "${DEVICE}"
            [[ -n "${GATE_ENO1_IP:-}" ]] && configure_interface_lua "eno1" "${GATE_ENO1_IP}" "${DEVICE}"
          else
            interactive_interface_config "${DEVICE}"
            interactive_network_params
          fi

          RUNTIME_NTP_ENABLE_B="${NTP_ENABLE}"
          run_sxn_for_current_gate "${DEVICE}"
      else
          echo "  → Gate B ignorée."
          RUNTIME_NTP_ENABLE_B="0"
      fi
      echo
    fi

    ####################################
    # 4) Interlink éventuel
    ####################################
    configure_interlink_between_gates
  else
    echo "[INFO] Mode 'dockers' : configuration SXN + interlink non lancée."
  fi

  echo
  echo "[OK] Orchestration terminée."
  echo "→ Détails complets dans ${LOG_FILE}"
}

main "$@"
