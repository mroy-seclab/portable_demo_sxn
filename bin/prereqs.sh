#!/usr/bin/env bash
set -euo pipefail

########################################
# 0. Localisation & lib commune
########################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
LIB_DIR="${ROOT_DIR}/lib"

# shellcheck disable=SC1091
source "${LIB_DIR}/common.sh"

########################################
# 1. Détection de l'OS
########################################

detect_os() {
  case "$(uname -s)" in
    Darwin)
      OS_FAMILY="macos"
      ;;
    Linux)
      OS_FAMILY="linux"
      ;;
    *)
      OS_FAMILY="unknown"
      ;;
  esac
}

########################################
# 2. Docker
########################################

install_docker_macos() {
  info "Docker n'est pas installé. Installation via Homebrew..."

  if ! command -v brew >/dev/null 2>&1; then
    warn "Homebrew n'est pas installé."

    if yes_no_default_yes "Installer Homebrew maintenant ?"; then
      info "Installation de Homebrew..."
      /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    else
      die "Homebrew est requis pour installer Docker Desktop automatiquement."
    fi
  fi

  info "Homebrew est présent."

  if yes_no_default_yes "Installer Docker Desktop via Homebrew ?"; then
    brew install --cask docker
    echo
    info "Docker Desktop installé."
    info "Ouvre l'application Docker Desktop une première fois,"
    info "accepte les permissions, puis relance ton script de setup."
  else
    warn "Installation automatique de Docker Desktop ignorée."
    warn "Installe Docker Desktop manuellement puis relance ce script."
  fi
}

ensure_docker() {
  if command -v docker >/dev/null 2>&1; then
    # Vérifie que le daemon répond
    if docker info >/dev/null 2>&1; then
      info "Docker déjà installé et opérationnel."
      return 0
    else
      warn "Docker est présent mais le daemon ne répond pas."
      warn "Lance Docker Desktop (ou le service docker) puis relance le script."
      exit 1
    fi
  fi

  # Docker non installé
  case "${OS_FAMILY}" in
    macos)
      install_docker_macos
      ;;
    linux)
      warn "Docker n'est pas installé."
      warn "Installe-le via ton gestionnaire de paquets (exemples) :"
      echo "  - Debian/Ubuntu : sudo apt update && sudo apt install docker.io"
      echo "  - RHEL/CentOS   : sudo dnf install docker-ce"
      echo "  - Arch Linux    : sudo pacman -S docker"
      echo "Ensuite, lance le service docker et relance ce script."
      exit 1
      ;;
    *)
      die "OS non supporté automatiquement pour l'installation de Docker. Installe Docker manuellement."
      ;;
  esac
}

########################################
# 3. tio
########################################

install_tio_macos() {
  if ! command -v brew >/dev/null 2>&1; then
    warn "Homebrew n'est pas installé."

    if yes_no_default_yes "Installer Homebrew maintenant pour pouvoir installer tio ?"; then
      info "Installation de Homebrew..."
      /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    else
      die "Homebrew est requis pour installer tio automatiquement sur macOS."
    fi
  fi

  info "Installation de tio via Homebrew..."
  brew install tio
}

install_tio_linux() {
  # On tente quelques gestionnaires de paquets connus
  if command -v apt >/dev/null 2>&1 || command -v apt-get >/dev/null 2>&1; then
    info "Installation de tio via apt (Debian/Ubuntu)..."
    sudo apt-get update -y || sudo apt update -y
    sudo apt-get install -y tio || sudo apt install -y tio
    return
  fi

  if command -v dnf >/dev/null 2>&1; then
    info "Installation de tio via dnf (Fedora/RHEL-like)..."
    sudo dnf install -y tio
    return
  fi

  if command -v pacman >/dev/null 2>&1; then
    info "Installation de tio via pacman (Arch)..."
    sudo pacman -S --noconfirm tio
    return
  fi

  if command -v zypper >/dev/null 2>&1; then
    info "Installation de tio via zypper (openSUSE)..."
    sudo zypper install -y tio
    return
  fi

  warn "Impossible de détecter un gestionnaire de paquets supporté pour installer tio automatiquement."
  warn "Installe tio manuellement (par ex. via le gestionnaire de paquets de ta distribution)"
  warn "puis relance ce script."
  exit 1
}

ensure_tio() {
  if command -v tio >/dev/null 2>&1; then
    info "tio déjà installé."
    return 0
  fi

  case "${OS_FAMILY}" in
    macos)
      if yes_no_default_yes "tio n'est pas installé. L'installer maintenant via Homebrew ?"; then
        install_tio_macos
      else
        die "tio est requis pour utiliser les scripts SXN (tio)."
      fi
      ;;
    linux)
      if yes_no_default_yes "tio n'est pas installé. Tenter une installation automatique (sudo requis) ?"; then
        install_tio_linux
      else
        die "tio est requis pour utiliser les scripts SXN (tio)."
      fi
      ;;
    *)
      die "OS non supporté automatiquement pour l'installation de tio. Installe-le manuellement."
      ;;
  esac
}

########################################
# 4. Main
########################################

main() {
  echo "=== Pré-requis Docker & tio pour la démo SXN ==="
  detect_os
  echo "OS détecté : ${OS_FAMILY}"
  echo

  ensure_docker
  echo

  ensure_tio
  echo

  echo "[OK] Pré-requis vérifiés : Docker et tio sont disponibles."
}

main "$@"
