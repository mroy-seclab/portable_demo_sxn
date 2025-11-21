#!/usr/bin/env bash

# Ce fichier est destiné à être "source".
# Il NE doit PAS modifier set -e/-u/-o pipefail du script appelant.

########################################
# Logging de base
########################################

info() {
  # stdout
  printf '[INFO] %s\n' "$*"
}

warn() {
  # stderr
  printf '[WARN] %s\n' "$*" >&2
}

error() {
  # stderr
  printf '[ERREUR] %s\n' "$*" >&2
}

die() {
  error "$*"
  exit 1
}

########################################
# Vérification de commandes
########################################

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    die "Commande requise introuvable : ${cmd}. Installe-la puis relance le script."
  fi
}

########################################
# Questions oui/non
########################################
# Convention :
#  - *_default_yes : Enter ⇒ oui
#  - *_default_no  : Enter ⇒ non
########################################

yes_no_default_yes() {
  local prompt="$1"
  local answer

  read -rp "${prompt} [Y/n] : " answer
  case "$answer" in
    [nN]|[nN][oO]) return 1 ;;
    *)             return 0 ;;  # défaut : oui
  esac
}

yes_no_default_no() {
  local prompt="$1"
  local answer

  read -rp "${prompt} [y/N] : " answer
  case "$answer" in
    [yY]|[yY][eE][sS]) return 0 ;;
    *)                 return 1 ;;  # défaut : non
  esac
}

########################################
# Helpers Docker de base
########################################

check_docker() {
  require_cmd docker

  if ! docker info >/dev/null 2>&1; then
    die "Docker ne semble pas démarré. Lance Docker Desktop (ou le service docker) puis relance le script."
  fi
}

detect_docker_compose() {
  if command -v docker-compose >/dev/null 2>&1; then
    echo "docker-compose"
    return 0
  fi

  if docker compose version >/dev/null 2>&1; then
    echo "docker compose"
    return 0
  fi

  die "Aucune commande docker-compose trouvée (ni 'docker-compose' ni 'docker compose')."
}
