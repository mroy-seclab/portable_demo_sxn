#!/usr/bin/env bash
set -euo pipefail

########################################
# 0. Paramètres (injectés par l'orchestrateur)
########################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_LUA_DIR="${SCRIPT_DIR}/base_SXN"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Variables passées par l'orchestrateur (avec défauts de secours)
: "${DEVICE:=/dev/cu.usbserial-UNKNOWN}"
: "${GATE:=A}"

: "${SXN_IFACE:=eno1}"
: "${SXN_IFACE_IP:=192.168.2.1/24}"

: "${SYSLOG_IFACE:=eno1}"
: "${SYSLOG_SERVER:=192.168.2.2}"
: "${SYSLOG_PORT:=6514}"
: "${SYSLOG_ENABLE:=1}"

: "${NTP_ENABLE:=1}"
: "${NTP_IFACE:=${SYSLOG_IFACE}}"
: "${NTP_SERVER:=${SYSLOG_SERVER}}"
: "${NTP_IFACE2:=}"
: "${NTP_SERVER2:=}"

: "${SNMP_ENABLE:=1}"
: "${SNMP_IFACE:=${SYSLOG_IFACE}}"

: "${SNMP_USER:=user}"
: "${SNMP_AUTH_PASS:=Password1}"
: "${SNMP_PRIV_PASS:=${SNMP_AUTH_PASS}}"

: "${SNMPD_PORT:=161}"
: "${SNMP_TRAP_REMOTE_IP:=${SNMPTRAPS_SERVER:-${SYSLOG_SERVER}}}"
: "${SNMP_TRAP_REMOTE_PORT:=162}"


: "${CERT_BASE_DIR:=${ROOT_DIR}/dockers/base_SXN/syslog-ng/cert}"

: "${SXN_ADMIN_USER:=admin}"
: "${SXN_ADMIN_PASSWORD:=SeclabFR2011!}"

REMOTE_CERT_FILE="${CERT_BASE_DIR}/server-cert.pem"
REMOTE_CA_FILE="${CERT_BASE_DIR}/fullchain_server.pem"

CLIENT_CERT_FILE="${CERT_BASE_DIR}/client-cert.pem"
CLIENT_CA_FILE="${CERT_BASE_DIR}/fullchain_client.pem"
CLIENT_PRIVATE_KEY_FILE="${CERT_BASE_DIR}/client-key.pem"

########################################
# 1. Fonctions utilitaires
########################################

ensure_dirs() {
  mkdir -p "${BASE_LUA_DIR}"
}

check_cert_files() {
  # On ne check les certs que si syslog est activé
  if [[ "${SYSLOG_ENABLE}" == "0" ]]; then
    return
  fi

  for f in "$REMOTE_CERT_FILE" "$REMOTE_CA_FILE" "$CLIENT_CERT_FILE" "$CLIENT_CA_FILE" "$CLIENT_PRIVATE_KEY_FILE"; do
    if [[ ! -f "$f" ]]; then
      echo "Erreur: fichier $f introuvable" >&2
      exit 1
    fi
  done
}

read_cert_files() {
  if [[ "${SYSLOG_ENABLE}" == "0" ]]; then
    return
  fi

  # On supprime les lignes vides, on garde une seule ligne avec "\n"
  REMOTE_CERT_FILE_CONTENT=$(awk 'NF {printf "%s\\n", $0}' < "$REMOTE_CERT_FILE")
  REMOTE_CA_FILE_CONTENT=$(awk 'NF {printf "%s\\n", $0}' < "$REMOTE_CA_FILE")
  CLIENT_CERT_FILE_CONTENT=$(awk 'NF {printf "%s\\n", $0}' < "$CLIENT_CERT_FILE")
  CLIENT_CA_FILE_CONTENT=$(awk 'NF {printf "%s\\n", $0}' < "$CLIENT_CA_FILE")
  CLIENT_PRIVATE_KEY_FILE_CONTENT=$(awk 'NF {printf "%s\\n", $0}' < "$CLIENT_PRIVATE_KEY_FILE")
}

########################################
# 2. Génération des scripts Lua (par gate)
########################################

generate_ntp_lua() {
  # Si NTP est désactivé, on ne génère rien
  if [[ "${NTP_ENABLE}" == "0" ]]; then
    return
  fi

  local CURRENT_TIME
  CURRENT_TIME=$(date -u +"%Y-%m-%dT%H:%M:%S")

  cat > "${BASE_LUA_DIR}/ntp_${GATE}.lua" <<EOF
-- ============================
-- SCRIPT : ntp_${GATE}.lua
-- Objet : configurer NTP dans la config 1 pour la gate ${GATE}
-- ============================

local GATE = "${GATE}"
local CONFIG_ID = 1

local ADMIN_USER = "${SXN_ADMIN_USER}"
local ADMIN_PASS = "${SXN_ADMIN_PASSWORD}"

local NTP_SERVER  = "${NTP_SERVER}"
local NTP_IFACE   = "${NTP_IFACE}"
local NTP_SERVER2 = "${NTP_SERVER2}"
local NTP_IFACE2  = "${NTP_IFACE2}"

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

-- Définir l'heure manuellement avant de passer en NTP
write("clock set time ${CURRENT_TIME}\\n")
msleep(2000)
expect(SYSTEM_PROMPT)

write("config edit " .. CONFIG_ID .. "\\n")
expect(CONFIG_PROMPT)

write("clock set sync mode ntp\\n")
expect(CONFIG_PROMPT)

-- Serveur primaire
write("ntp set server primary type unicast addr " .. NTP_SERVER .. "\\n")
expect(CONFIG_PROMPT)
write("ntp bind on iface " .. NTP_IFACE .. "\\n")
expect(CONFIG_PROMPT)

-- Optionnel : serveur secondaire + 2ᵉ interface
if NTP_SERVER2 ~= "" then
  write("ntp set server secondary type unicast addr " .. NTP_SERVER2 .. "\\n")
  expect(CONFIG_PROMPT)
  if NTP_IFACE2 ~= "" and NTP_IFACE2 ~= NTP_IFACE then
    write("ntp bind on iface " .. NTP_IFACE2 .. "\\n")
    expect(CONFIG_PROMPT)
  end
end

write("exit\\n")
expect(SYSTEM_PROMPT)

write("config save " .. CONFIG_ID .. "\\n")
expect(SYSTEM_PROMPT)

exit(0)
EOF
}

generate_snmp_lua() {
  # Si SNMP est désactivé, ne génère rien
  if [[ "${SNMP_ENABLE}" == "0" ]]; then
    return
  fi

  cat > "${BASE_LUA_DIR}/snmp_${GATE}.lua" <<EOF
-- ============================
-- SCRIPT : snmp_${GATE}.lua
-- Objet : configurer SNMPd + SNMP traps dans la config 1 pour la gate ${GATE}
-- ============================

local GATE = "${GATE}"
local CONFIG_ID = 1

local ADMIN_USER = "${SXN_ADMIN_USER}"
local ADMIN_PASS = "${SXN_ADMIN_PASSWORD}"

local SNMP_IFACE            = "${SNMP_IFACE}"
local SNMP_USER             = "${SNMP_USER}"
local SNMP_AUTH_PASS        = "${SNMP_AUTH_PASS}"
local SNMP_PRIV_PASS        = "${SNMP_PRIV_PASS}"
local SNMPD_PORT            = ${SNMPD_PORT}
local SNMP_TRAP_REMOTE_IP   = "${SNMP_TRAP_REMOTE_IP}"
local SNMP_TRAP_REMOTE_PORT = ${SNMP_TRAP_REMOTE_PORT}

local SYSTEM_PROMPT = "SecOS-" .. GATE .. ">"
local CONFIG_PROMPT = "SecOS-" .. GATE .. " \\\(config\\\)>"

msleep(500)
write("\\n")

-- Login si nécessaire
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

-- Entrer en mode config
write("config edit " .. CONFIG_ID .. "\\n")
expect(CONFIG_PROMPT)

--------------------------------------------------
-- SNMPd (agent SNMP, port 161 par défaut)
--------------------------------------------------

write("snmpd bind on iface " .. SNMP_IFACE .. "\\n")
expect(CONFIG_PROMPT)

write("snmpd set user " .. SNMP_USER .. "\\n")
local rc1 = expect("Enter Authentication Passphrase:", 5000)
if rc1 == 1 then
  write(SNMP_AUTH_PASS .. "\\n")
  expect("Enter Privacy Passphrase:", 5000)
  write(SNMP_PRIV_PASS .. "\\n")
  expect(CONFIG_PROMPT)
else
  -- Au cas où le prompt ne correspond pas exactement, on revient au prompt config
  expect(CONFIG_PROMPT)
end

write("snmpd set port " .. tostring(SNMPD_PORT) .. "\\n")
expect(CONFIG_PROMPT)

write("snmpd enable\\n")
expect(CONFIG_PROMPT)

--------------------------------------------------
-- SNMP traps (manager distant)
--------------------------------------------------

write("snmptrap bind on iface " .. SNMP_IFACE .. "\\n")
expect(CONFIG_PROMPT)

write("snmptrap set remote " .. SNMP_TRAP_REMOTE_IP .. " port " .. tostring(SNMP_TRAP_REMOTE_PORT) .. "\\n")
expect(CONFIG_PROMPT)

write("snmptrap set user " .. SNMP_USER .. " auth sha priv aes\\n")
local rc2 = expect("Enter Authentication Passphrase:", 5000)
if rc2 == 1 then
  write(SNMP_AUTH_PASS .. "\\n")
  expect("Enter Privacy Passphrase:", 5000)
  write(SNMP_PRIV_PASS .. "\\n")
  expect(CONFIG_PROMPT)
else
  expect(CONFIG_PROMPT)
end

write("snmptrap enable\\n")
expect(CONFIG_PROMPT)


write("exit\\n")
expect(SYSTEM_PROMPT)

write("config save " .. CONFIG_ID .. "\\n")
expect(SYSTEM_PROMPT)

exit(0)
EOF
}

generate_syslog_basic_lua() {
  cat > "${BASE_LUA_DIR}/syslog_basic_${GATE}.lua" <<EOF
-- syslog_basic_${GATE}.lua
-- Pas d’import TLS, pas de clés

local GATE="${GATE}"
local CONFIG_ID=1

local ADMIN_USER="${SXN_ADMIN_USER}"
local ADMIN_PASS="${SXN_ADMIN_PASSWORD}"

local SYSLOG_IFACE="${SYSLOG_IFACE}"
local SYSLOG_SERVER="${SYSLOG_SERVER}"
local SYSLOG_PORT=${SYSLOG_PORT}

local SYSTEM_PROMPT="SecOS-" .. GATE .. ">"
local CONFIG_PROMPT="SecOS-" .. GATE .. " \\\(config\\\)>"

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

write("config edit " .. CONFIG_ID .. "\\n")
expect(CONFIG_PROMPT)

write("syslog bind on iface " .. SYSLOG_IFACE .. "\\n")
expect(CONFIG_PROMPT)

write("syslog set remote protocol tcp\\n")
expect(CONFIG_PROMPT)

write("syslog set remote addr " .. SYSLOG_SERVER .. " port " .. SYSLOG_PORT .. "\\n")
expect(CONFIG_PROMPT)

write("syslog enable remote\\n")
expect(CONFIG_PROMPT)

write("exit\\n")
expect(SYSTEM_PROMPT)

write("config save " .. CONFIG_ID .. "\\n")
expect(SYSTEM_PROMPT)

exit(0)
EOF
}


generate_syslog_tls_lua() {
  if [[ "${SYSLOG_ENABLE}" == "0" ]]; then
    return
  fi

  cat > "${BASE_LUA_DIR}/syslog_tls_${GATE}.lua" <<EOF
-- =======================================================
-- SCRIPT : syslog_${GATE}.lua
-- Objet : configurer syslog TLS distant dans la config 1 pour la gate ${GATE}
-- =======================================================

local GATE = "${GATE}"
local CONFIG_ID = 1

local ADMIN_USER = "${SXN_ADMIN_USER}"
local ADMIN_PASS = "${SXN_ADMIN_PASSWORD}"

local SYSLOG_IFACE  = "${SYSLOG_IFACE}"
local SYSLOG_SERVER = "${SYSLOG_SERVER}"
local SYSLOG_PORT   = ${SYSLOG_PORT}

-- chemins vers les fichiers PEM sur la machine hôte
local REMOTE_CERT_PATH  = "${REMOTE_CERT_FILE}"
local REMOTE_CA_PATH    = "${REMOTE_CA_FILE}"

local CLIENT_CERT_PATH  = "${CLIENT_CERT_FILE}"
local CLIENT_CA_PATH    = "${CLIENT_CA_FILE}"
local CLIENT_KEY_PATH   = "${CLIENT_PRIVATE_KEY_FILE}"

local SYSTEM_PROMPT = "SecOS-" .. GATE .. ">"
local CONFIG_PROMPT = "SecOS-" .. GATE .. " \\\(config\\\)>"

local IMPORT_REMOTE_BLOCK1 = "Paste certificate here then type Ctrl"
local IMPORT_REMOTE_BLOCK2 = "Paste certificate chain here then type Ctrl"
local IMPORT_REMOTE_BLOCK3 = "Paste key here then type Ctrl"

-- Lit un fichier PEM local et l'envoie **ligne par ligne** sur la console SXN
local function send_pem_file(path)
  local f, err = io.open(path, "r")
  if not f then
    print("ERROR: cannot open " .. path .. ": " .. tostring(err))
    exit(1)
  end

  local data = f:read("*a")
  f:close()

  if not data or data == "" then
    print("ERROR: empty PEM file: " .. path)
    exit(1)
  end

  -- on garde en mémoire si le fichier se termine par un newline
  local ends_with_nl = (data:match("\n$") ~= nil)

  -- parse ligne par ligne, tolérant \n / \r\n
  for line in data:gmatch("([^\r\n]*)\r?\n") do
    -- on envoie aussi les lignes vides
    write(line .. "\\n")
    msleep(30)
  end

  -- si le PEM ne se termine pas par un \n, on force une ligne vide supplémentaire
  if not ends_with_nl then
    write("\\n")
    msleep(30)
  end
end

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

write("syslog bind on iface " .. SYSLOG_IFACE .. "\\n")
expect(CONFIG_PROMPT)

write("syslog set remote protocol tcp\\n")
expect(CONFIG_PROMPT)

write("syslog set remote addr " .. SYSLOG_SERVER .. " port " .. SYSLOG_PORT .. "\\n")
expect(CONFIG_PROMPT)

write("syslog enable remote\\n")
expect(CONFIG_PROMPT)

write("syslog set remote tls mode on\\n")
expect(CONFIG_PROMPT)

--------------------------------------------------
-- 1) Import remote cert PEM
--------------------------------------------------
write("syslog import remote cert pem\\n")
expect(IMPORT_REMOTE_BLOCK1)
msleep(100)

send_pem_file(REMOTE_CERT_PATH)

write("\\4")   -- Ctrl+D
msleep(500)

--------------------------------------------------
-- 2) Import remote CA chain
--------------------------------------------------
expect(IMPORT_REMOTE_BLOCK2)
msleep(100)

send_pem_file(REMOTE_CA_PATH)

write("\\4")
msleep(500)

expect(CONFIG_PROMPT)

--------------------------------------------------
-- 3) Auth client par cert
--------------------------------------------------
write("syslog set client tls auth cert\\n")
expect(CONFIG_PROMPT)

-- Import client cert
write("syslog import client cert pem\\n")
expect(IMPORT_REMOTE_BLOCK1)
msleep(100)

send_pem_file(CLIENT_CERT_PATH)

write("\\4")
msleep(500)

-- Import client key
expect(IMPORT_REMOTE_BLOCK3)
msleep(100)

send_pem_file(CLIENT_KEY_PATH)

write("\\4")
msleep(500)

-- Import client CA chain
expect(IMPORT_REMOTE_BLOCK2)
msleep(100)

send_pem_file(CLIENT_CA_PATH)

write("\\4")
msleep(500)

expect(CONFIG_PROMPT)

write("exit\\n")
expect(SYSTEM_PROMPT)

write("config save " .. CONFIG_ID .. "\\n")
expect(SYSTEM_PROMPT)

exit(0)
EOF
}

generate_check_services_lua() {
  cat > "${BASE_LUA_DIR}/check_services_${GATE}.lua" <<EOF
-- =======================================================
-- SCRIPT : check_services_${GATE}.lua
-- Objet : vérifier NTP et syslog sur le SXN
-- =======================================================

local GATE = "${GATE}"
local ADMIN_USER = "${SXN_ADMIN_USER}"
local ADMIN_PASS = "${SXN_ADMIN_PASSWORD}"

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

-- Vérification NTP

write("clock show sync status\\n")

-- Vérification syslog
expect(SYSTEM_PROMPT)
write("syslog show remote\\n")
expect(SYSTEM_PROMPT)

write("snmpd show\\n")
expect(SYSTEM_PROMPT)
write("snmptrap show\\n")
expect(SYSTEM_PROMPT)
msleep(1000)
write("exit\\n")
msleep(500)
exit(0)
EOF
}

generate_reboot_lua() {
  # Utilisé après config NTP
  cat > "${BASE_LUA_DIR}/reboot_and_wait_login_${GATE}.lua" <<EOF
-- reboot_and_wait_login_${GATE}.lua
-- Redémarre le SXN puis attend le prompt "Sec-XN-<GATE> login:"

local GATE = "${GATE}"

local SYSTEM_PROMPT = "SecOS-" .. GATE .. ">"
local LOGIN_PROMPT  = "Sec-XN-" .. GATE .. " login:"

msleep(500)
write("\\n")

local rc = expect(SYSTEM_PROMPT, 2000)

if rc == 1 then
  write("system reboot\\n")
  msleep(2000)
end

local rc2 = expect(LOGIN_PROMPT, 600000)

if rc2 ~= 1 then
  print("ERROR: login prompt 'Sec-XN-" .. GATE .. " login:' non vu après reboot.")
  exit(1)
end

exit(0)
EOF
}

########################################
# 3. Orchestration des scripts Lua via tio
########################################

run_tio_sequence() {
  local step=1

  if [[ "${NTP_ENABLE}" != "0" ]]; then
    echo "[${step}] Configuration NTP (gate ${GATE})..."
    tio --script-file "${BASE_LUA_DIR}/ntp_${GATE}.lua" "${DEVICE}"
    ((step++))

    echo "[${step}] Reboot SXN et attente du login (gate ${GATE})..."
    tio --script-file "${BASE_LUA_DIR}/reboot_and_wait_login_${GATE}.lua" "${DEVICE}"
    ((step++))
  else
    echo "[NTP] NTP désactivé pour gate ${GATE} (pas de reboot auto)."
  fi

  if [[ "${SYSLOG_ENABLE}" != "0" ]]; then
    if [[ "${USE_DOCKER_SYSLOG}" == "1" ]]; then
      echo "[${step}] Configuration syslog TLS + import PKI (gate ${GATE})..."
      tio --script-file "${BASE_LUA_DIR}/syslog_tls_${GATE}.lua" "${DEVICE}"
      echo "[${step}] Reboot SXN et attente du login (gate ${GATE})..."
      tio --script-file "${BASE_LUA_DIR}/reboot_and_wait_login_${GATE}.lua" "${DEVICE}"
      ((step++))
    else
      echo "[${step}] Configuration syslog simple (pas de TLS, pas d'import) (gate ${GATE})..."
      tio --script-file "${BASE_LUA_DIR}/syslog_basic_${GATE}.lua" "${DEVICE}"
      echo "[${step}] Reboot SXN et attente du login (gate ${GATE})..."
      tio --script-file "${BASE_LUA_DIR}/reboot_and_wait_login_${GATE}.lua" "${DEVICE}"
      ((step++))
    fi
    ((step++))
  else
    echo "[SYSLOG] Syslog désactivé pour gate ${GATE}."
  fi

  if [[ "${SNMP_ENABLE}" != "0" ]]; then
    echo "[${step}] Configuration SNMPd + SNMP traps (gate ${GATE})..."
    tio --script-file "${BASE_LUA_DIR}/snmp_${GATE}.lua" "${DEVICE}"
    ((step++))

    echo "[${step}] Reboot SXN et attente du login (gate ${GATE})..."
    tio --script-file "${BASE_LUA_DIR}/reboot_and_wait_login_${GATE}.lua" "${DEVICE}"
    ((step++))
  else
    echo "[SNMP] SNMP désactivé pour gate ${GATE}."
  fi

  echo "[OK] Configuration SXN terminée pour gate ${GATE}."
}



########################################
# 4. main
########################################

main() {
  echo "=== Setup SXN via tio ==="
  echo "Guichet        : ${GATE}"
  echo "Device         : ${DEVICE}"
  echo "SXN iface      : ${SXN_IFACE}"
  echo "SXN iface IP   : ${SXN_IFACE_IP}"
  echo "Syslog iface   : ${SYSLOG_IFACE}"
  echo "Syslog serv    : ${SYSLOG_SERVER}:${SYSLOG_PORT} (enable=${SYSLOG_ENABLE})"
  echo "NTP enable     : ${NTP_ENABLE}"
  echo "NTP server     : ${NTP_SERVER} (${NTP_IFACE})"
  echo "NTP server2    : ${NTP_SERVER2:-<none>} (${NTP_IFACE2:-<none>})"
  echo "Certs dir      : ${CERT_BASE_DIR}"
  echo "SXN admin      : ${SXN_ADMIN_USER}"
  echo

  ensure_dirs
  check_cert_files
  read_cert_files

  generate_ntp_lua

  if [[ "${SYSLOG_ENABLE}" != "0" ]]; then
    if [[ "${USE_DOCKER_SYSLOG}" == "1" ]]; then
      # Syslog vers le docker → on génère uniquement la version TLS + PKI
      generate_syslog_tls_lua
    else
      # Syslog vers une IP externe → on génère uniquement la version "basic"
      generate_syslog_basic_lua
    fi
  fi
  
  generate_snmp_lua
  generate_check_services_lua
  generate_reboot_lua

  run_tio_sequence
}

main
