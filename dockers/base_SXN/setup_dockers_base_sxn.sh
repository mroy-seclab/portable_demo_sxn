#!/usr/bin/env bash
set -euo pipefail

##############################################
# 0. Variables de base (paramétrables)
##############################################

# Paramètres PKI / syslog (prêts pour l’orchestrateur)
: "${SYSLOG_SERVER_IP:=192.168.2.2}"
: "${SYSLOG_SAN_DNS:=server.syslog.local}"
: "${P12_PASSWORD:=seclab}"          # mot de passe PKCS#12
: "${SYSLOG_LISTEN_PORT:=6514}"      # port TLS syslog-ng (host et container)

# Répertoire du script (dockers/base_SXN)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
LIB_DIR="${ROOT_DIR}/lib"

# shellcheck disable=SC1091
source "${LIB_DIR}/common.sh"


# Racine du projet base_SXN (paramétrable, mais par défaut le dossier du script)
: "${BASE_DIR:=${SCRIPT_DIR}}"

SYSLOG_DIR="${BASE_DIR}/syslog-ng"
SYSLOG_CONFIG_DIR="${SYSLOG_DIR}/config"
SYSLOG_CERT_DIR="${SYSLOG_DIR}/cert"
SYSLOG_LOG_DIR="${SYSLOG_DIR}/logs"

NTP_DIR="${BASE_DIR}/ntp"
NTP_CONFIG_DIR="${NTP_DIR}/config"

ZBX_DIR="${BASE_DIR}/zabbix-snmptraps"
ZBX_CONFIG_DIR="${ZBX_DIR}/config"
ZBX_TRAPS_DIR="${ZBX_DIR}/traps"

DC=()   # sera rempli dans detect_docker_compose()

echo "=== Setup base_SXN ==="
echo "Racine projet : ${BASE_DIR}"
echo "IP syslog     : ${SYSLOG_SERVER_IP}"
echo "SAN DNS       : ${SYSLOG_SAN_DNS}"
echo "Port TLS      : ${SYSLOG_LISTEN_PORT}"
echo

##############################################
# 1. Fonctions
##############################################

create_directories() {
  ##############################################
  # Création de l'arborescence
  ##############################################
  echo "Création de l'arborescence..."
  mkdir -p \
    "${SYSLOG_CONFIG_DIR}" \
    "${SYSLOG_CERT_DIR}" \
    "${SYSLOG_LOG_DIR}" \
    "${NTP_CONFIG_DIR}" \
    "${ZBX_CONFIG_DIR}" \
    "${ZBX_TRAPS_DIR}"

  echo "[OK] Dossiers créés sous ${BASE_DIR}"
  echo
}

generate_pki() {
  ##############################################
  # Génération de la PKI locale (syslog-ng)
  ##############################################
  cd "${BASE_DIR}"

  if [[ -f "${SYSLOG_CERT_DIR}/ca.pem" ]]; then
    echo "PKI déjà présente dans ${SYSLOG_CERT_DIR}, on ne régénère pas."
  else
    echo "Génération de la CA..."
    openssl genrsa -out "${SYSLOG_CERT_DIR}/ca-key.pem" 4096

    openssl req -x509 -new -nodes \
      -key "${SYSLOG_CERT_DIR}/ca-key.pem" \
      -sha256 -days 3650 \
      -subj "/C=FR/ST=IDF/L=Paris/O=Seclab/CN=Seclab-Root-CA" \
      -out "${SYSLOG_CERT_DIR}/ca.pem"

    echo "Génération clé + CSR serveur..."
    openssl genrsa -out "${SYSLOG_CERT_DIR}/server-key.pem" 4096

    openssl req -new \
      -key "${SYSLOG_CERT_DIR}/server-key.pem" \
      -subj "/C=FR/ST=IDF/L=Paris/O=Seclab/CN=${SYSLOG_SERVER_IP}" \
      -out "${SYSLOG_CERT_DIR}/server.csr"

    cat > "${SYSLOG_CERT_DIR}/ext.cnf" <<EOF
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = IP:${SYSLOG_SERVER_IP}, DNS:${SYSLOG_SAN_DNS}
EOF

    echo "Signature du certificat serveur..."
    openssl x509 -req \
      -in "${SYSLOG_CERT_DIR}/server.csr" \
      -CA "${SYSLOG_CERT_DIR}/ca.pem" -CAkey "${SYSLOG_CERT_DIR}/ca-key.pem" -CAcreateserial \
      -out "${SYSLOG_CERT_DIR}/server-cert.pem" -days 365 \
      -extfile "${SYSLOG_CERT_DIR}/ext.cnf"

    echo "Génération clé + CSR client..."
    openssl genrsa -out "${SYSLOG_CERT_DIR}/client-key.pem" 4096

    openssl req -new \
      -key "${SYSLOG_CERT_DIR}/client-key.pem" \
      -subj "/C=FR/ST=IDF/L=Paris/O=Seclab/CN=syslog-client" \
      -out "${SYSLOG_CERT_DIR}/client.csr"

    cat > "${SYSLOG_CERT_DIR}/client-ext.cnf" << 'EOF'
extendedKeyUsage = clientAuth
EOF

    echo "Signature du certificat client..."
    openssl x509 -req \
      -in "${SYSLOG_CERT_DIR}/client.csr" \
      -CA "${SYSLOG_CERT_DIR}/ca.pem" -CAkey "${SYSLOG_CERT_DIR}/ca-key.pem" -CAcreateserial \
      -out "${SYSLOG_CERT_DIR}/client-cert.pem" -days 365 \
      -extfile "${SYSLOG_CERT_DIR}/client-ext.cnf"

    echo "Vérification des certificats..."
    openssl verify -CAfile "${SYSLOG_CERT_DIR}/ca.pem" "${SYSLOG_CERT_DIR}/server-cert.pem"
    openssl verify -CAfile "${SYSLOG_CERT_DIR}/ca.pem" "${SYSLOG_CERT_DIR}/client-cert.pem"
  fi

  # Fullchain serveur (cert + CA)
  cat "${SYSLOG_CERT_DIR}/server-cert.pem" "${SYSLOG_CERT_DIR}/ca.pem" > "${SYSLOG_CERT_DIR}/fullchain_server.pem"
  openssl verify -CAfile "${SYSLOG_CERT_DIR}/ca.pem" "${SYSLOG_CERT_DIR}/fullchain_server.pem"

  # Fullchain client (cert + CA)
  cat "${SYSLOG_CERT_DIR}/client-cert.pem" "${SYSLOG_CERT_DIR}/ca.pem" > "${SYSLOG_CERT_DIR}/fullchain_client.pem"
  openssl verify -CAfile "${SYSLOG_CERT_DIR}/ca.pem" "${SYSLOG_CERT_DIR}/fullchain_client.pem"

  # Fichiers PKCS#12
  local SERVER_P12="${SYSLOG_CERT_DIR}/server-fullchain.p12"
  local CLIENT_P12="${SYSLOG_CERT_DIR}/client-fullchain.p12"

  # PKCS#12 serveur avec mot de passe
  openssl pkcs12 -export \
    -inkey "${SYSLOG_CERT_DIR}/server-key.pem" \
    -in "${SYSLOG_CERT_DIR}/server-cert.pem" \
    -certfile "${SYSLOG_CERT_DIR}/fullchain_server.pem" \
    -name "syslog-server" \
    -passout pass:"${P12_PASSWORD}" \
    -out "${SERVER_P12}"

  # PKCS#12 client avec mot de passe
  openssl pkcs12 -export \
    -inkey "${SYSLOG_CERT_DIR}/client-key.pem" \
    -in "${SYSLOG_CERT_DIR}/client-cert.pem" \
    -certfile "${SYSLOG_CERT_DIR}/fullchain_client.pem" \
    -name "syslog-client" \
    -passout pass:"${P12_PASSWORD}" \
    -out "${CLIENT_P12}"

  echo "[OK] PKI locale prête (${SYSLOG_CERT_DIR})"

  local SERVER_B64="${SERVER_P12}.b64"
  local CLIENT_B64="${CLIENT_P12}.b64"

  echo "===== SERVER_P12_BASE64 ====="
  openssl base64 -in "${SERVER_P12}" | tr -d '\n' > "${SERVER_B64}"
  echo
  echo "→ Base64 serveur      : ${SERVER_B64}"
  echo
  echo "===== CLIENT_P12_BASE64 ====="
  openssl base64 -in "${CLIENT_P12}" | tr -d '\n' > "${CLIENT_B64}"
  echo
  echo "→ Base64 client       : ${CLIENT_B64}"
  echo
}

generate_syslog_ng_conf() {
  ##############################################
  # syslog-ng.conf (TLS + mTLS)
  ##############################################
  local SYSLOG_CONF_FILE="${SYSLOG_CONFIG_DIR}/syslog-ng.conf"

  if [[ -f "${SYSLOG_CONF_FILE}" ]]; then
    echo "syslog-ng.conf existe déjà, on ne le régénère pas."
  else
    echo "Création de syslog-ng.conf..."
    cat > "${SYSLOG_CONF_FILE}" << EOF
@version: 4.10
@include "scl.conf"

source s_tls {
    network(
        transport("tls")
        port(${SYSLOG_LISTEN_PORT})

        tls(
            key-file("/cert/server-key.pem")
            cert-file("/cert/server-cert.pem")
            ca-file("/cert/ca.pem")
            peer-verify(required-trusted)
        )
    );
};

destination d_messages {
    file("/var/log/messages");
};

log {
    source(s_tls);
    destination(d_messages);
};
EOF
  fi

  echo "[OK] Configuration syslog-ng prête (${SYSLOG_CONF_FILE})"
  echo
}

generate_docker_compose() {
  ##############################################
  # docker-compose.yml
  ##############################################
  local COMPOSE_FILE="${BASE_DIR}/docker-compose.yml"

  if [[ -f "${COMPOSE_FILE}" ]]; then
    echo "docker-compose.yml existe déjà, on ne le régénère pas."
  else
    echo "Création de docker-compose.yml..."
    cat > "${COMPOSE_FILE}" << EOF
version: "3.9"

services:
  syslog-ng:
    image: balabit/syslog-ng:latest
    container_name: syslog-ng
    restart: unless-stopped
    cap_add:
      - SETPCAP
    ports:
      - "514:514/udp"
      - "601:601"
      - "${SYSLOG_LISTEN_PORT}:${SYSLOG_LISTEN_PORT}"
    volumes:
      - ./syslog-ng/config/syslog-ng.conf:/etc/syslog-ng/syslog-ng.conf:ro
      - ./syslog-ng/cert:/cert:ro
      - ./syslog-ng/logs:/var/log
    networks:
      - base_sxn

  ntp:
    build: .
    image: cturra/ntp:latest
    container_name: ntp
    restart: always
    ports:
      - 123:123/udp
    environment:
      - NTP_SERVERS=time.cloudflare.com
      - LOG_LEVEL=0
#      - TZ=America/Vancouver
#      - NOCLIENTLOG=true
#      - ENABLE_NTS=true
    networks:
     - base_sxn

  zabbix-snmptraps:
    image: zabbix/zabbix-snmptraps:alpine-latest
    container_name: zabbix-snmptraps
    restart: unless-stopped
    ports:
      - "162:1162/udp"
    volumes:
      - ./zabbix-snmptraps/traps:/var/lib/zabbix/snmptraps
    networks:
      - base_sxn

networks:
  base_sxn:
    driver: bridge
EOF
  fi

  echo "[OK] docker-compose.yml prêt (${COMPOSE_FILE})"
  echo
}

start_containers() {
  ##############################################
  # Lancement des conteneurs
  ##############################################
  echo "Lancement des conteneurs via docker compose..."
  cd "${BASE_DIR}"
  "${DC[@]}" up -d

  echo
  echo "=== État des services ==="
  "${DC[@]}" ps
  echo
}

configure_zabbix_snmp() {
  ##############################################
  # snmptrapd.conf (Zabbix SNMP traps)
  ##############################################
  local CONTAINER_NAME="zabbix-snmptraps"
  echo "[*] Updating /etc/snmp/snmptrapd.conf inside container..."

  docker exec -u root "${CONTAINER_NAME}" sh -lc '
    CONF="/etc/snmp/snmptrapd.conf"

    # Show permissions (debug)
    ls -l "$CONF" || echo "No $CONF yet"

    # Ensure doNotRetainNotificationLogs is enabled
    if ! grep -q "doNotRetainNotificationLogs" "$CONF" 2>/dev/null; then
      echo "doNotRetainNotificationLogs yes" >> "$CONF"
    else
      echo "doNotRetainNotificationLogs yes" >> "$CONF"
    fi

    # Add SNMPv3 user
    if ! grep -q "^createUser user " "$CONF" 2>/dev/null; then
      echo "createUser user SHA Password1 AES Password1" >> "$CONF"
    fi

    # Authorize that user for logging
    if ! grep -q "^authUser log user" "$CONF" 2>/dev/null; then
      echo "authUser log user" >> "$CONF"
    fi
  '

  echo "[*] Restarting snmptrapd inside container..."
  docker restart zabbix-snmptraps

  echo "[*] Done. Container '${CONTAINER_NAME}' is running with updated snmptrapd.conf."
  echo
}

run_tests() {
  ##############################################
  # Tests rapides
  ##############################################
  echo "Test rapide handshake TLS mTLS (syslog-ng) :"
  echo "(tu peux relancer cette commande à la main si besoin)"

  openssl s_client \
    -connect "127.0.0.1:${SYSLOG_LISTEN_PORT}" \
    -cert "${SYSLOG_CERT_DIR}/client-cert.pem" \
    -key "${SYSLOG_CERT_DIR}/client-key.pem" \
    -CAfile "${SYSLOG_CERT_DIR}/ca.pem" \
    -no_tls1_3 </dev/null || true

  echo
  echo "Aperçu des logs syslog-ng :"
  docker logs syslog-ng | tail -n 10 || true
  echo

  echo "Tracking NTP (cturra/ntp) :"
  #docker exec -it ntp chronyc tracking || echo "chronyc non dispo ou erreur."
  #docker exec -it ntp chronyc sources || echo "chronyc non dispo ou erreur."
  echo
}

main() {
  check_docker

  local compose_cmd
  compose_cmd="$(detect_docker_compose)"
  # Conversion en tableau pour pouvoir appeler "${DC[@]}"
  read -r -a DC <<< "${compose_cmd}"
  echo "[OK] Commande docker compose détectée : ${DC[*]}"
  echo

  create_directories
  generate_pki
  generate_syslog_ng_conf
  generate_docker_compose
  start_containers
  configure_zabbix_snmp
  run_tests

  echo "=== Fin du setup base_SXN ==="
  echo "Racine projet : ${BASE_DIR}"
  echo "syslog-ng : ${SYSLOG_DIR}"
  echo "ntp      : ${NTP_DIR}"
  echo "zabbix   : ${ZBX_DIR}"
  echo
  echo "Suivre les logs syslog-ng :"
  echo "  docker logs -f syslog-ng"
}


main
