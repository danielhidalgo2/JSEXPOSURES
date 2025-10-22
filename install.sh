#!/usr/bin/env bash
set -Eeuo pipefail

# ===== Colors =====
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

# ===== Globals =====
DETECTED_ID=""; DETECTED_ID_LIKE=""
SCRIPT_DIR="$(pwd)"
VENV_DIR="${SCRIPT_DIR}/jsexposures_venv"
WANTS_VENV_ONLY="false"
WANTS_NO_VENV="false"

trap 'printf "%b[!] An error occurred. Aborting.%b\n" "$RED" "$NC"' ERR

# ===== Utils =====
detect_os() {
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    DETECTED_ID="${ID:-}"; DETECTED_ID_LIKE="${ID_LIKE:-}"
    return 0
  fi
  printf "%b[!] Could not detect OS via /etc/os-release%b\n" "$RED" "$NC"
  return 1
}

check_cmd() { command -v "$1" >/dev/null 2>&1; }

check_venv_available() { python3 - <<'PY' 2>/dev/null || exit 1
import venv
PY
}

create_requirements_if_missing() {
  if [[ ! -f "requirements.txt" ]]; then
    cat > requirements.txt <<'EOF'
requests>=2.28.0
urllib3>=1.26.0
EOF
    printf "%b[+] Created basic requirements.txt%b\n" "$BLUE" "$NC"
  fi
}

# ===== System-wide installs =====
install_arch() {
  printf "%b[+] Arch-like detected. Installing system packages with pacman...%b\n" "$BLUE" "$NC"
  # Evita partial upgrade y prompts
  if sudo pacman -S --needed --noconfirm python python-pip python-requests python-urllib3; then
    printf "%b[+] Dependencies installed.%b\n" "$GREEN" "$NC"
    return 0
  fi
  # Fallback si la DB está desactualizada
  if sudo pacman -Sy --needed --noconfirm python python-pip python-requests python-urllib3; then
    printf "%b[+] Dependencies installed (after -Sy).%b\n" "$GREEN" "$NC"
    return 0
  fi
  printf "%b[!] pacman installation failed%b\n" "$RED" "$NC"
  return 1
}

install_debian() {
  printf "%b[+] Debian/Ubuntu-like detected. Installing system packages with apt-get...%b\n" "$BLUE" "$NC"
  sudo apt-get update -y
  if sudo apt-get install -y python3 python3-pip python3-venv python3-requests python3-urllib3; then
    printf "%b[+] Dependencies installed.%b\n" "$GREEN" "$NC"
    return 0
  fi
  printf "%b[!] apt-get installation failed%b\n" "$RED" "$NC"
  return 1
}

# ===== venv support =====
install_venv_arch() {
  printf "%b[+] Installing virtualenv on Arch...%b\n" "$BLUE" "$NC"
  sudo pacman -S --needed --noconfirm python python-pip python-virtualenv || true
}

install_venv_debian() {
  printf "%b[+] Installing python3-venv/virtualenv on Debian/Ubuntu...%b\n" "$BLUE" "$NC"
  sudo apt-get update -y
  sudo apt-get install -y python3 python3-pip python3-venv python3-virtualenv || true
}

install_venv_support() {
  if [[ "$DETECTED_ID" == "arch" || "$DETECTED_ID_LIKE" == *"arch"* ]]; then
    install_venv_arch
  elif [[ "$DETECTED_ID" == "debian" || "$DETECTED_ID_LIKE" == *"debian"* ]]; then
    install_venv_debian
  fi
  # Asegura virtualenv como último recurso para crear venvs
  python3 -m pip install --user --upgrade pip >/dev/null 2>&1 || true
  python3 -m pip install --user virtualenv >/dev/null 2>&1 || true
}

setup_venv() {
  printf "%b[+] Setting up Python virtual environment...%b\n" "$BLUE" "$NC"

  check_cmd python3 || { printf "%b[!] python3 not found in PATH%b\n" "$RED" "$NC"; return 1; }

  if ! check_venv_available; then
    printf "%b[!] Python venv module not available. Trying to install support...%b\n" "$YELLOW" "$NC"
    detect_os || true
    install_venv_support || true
  fi

  # Intenta venv primero
  if ! python3 -m venv "$VENV_DIR" 2>/dev/null; then
    printf "%b[!] venv failed, trying virtualenv...%b\n" "$YELLOW" "$NC"
    python3 -m virtualenv "$VENV_DIR"
  fi

  # shellcheck disable=SC1090
  source "${VENV_DIR}/bin/activate"
  python -m pip install --upgrade pip

  if [[ -f "requirements.txt" ]]; then
    python -m pip install -r requirements.txt
  else
    printf "%b[+] requirements.txt not found, installing basic deps...%b\n" "$BLUE" "$NC"
    python -m pip install requests urllib3
    python -m pip freeze > requirements.txt
    printf "%b[+] Created requirements.txt from current environment%b\n" "$BLUE" "$NC"
  fi

  printf "%b[✓] Virtual environment ready.%b\n" "$GREEN" "$NC"
  printf "%b[+] To activate later: %bsource jsexposures_venv/bin/activate%b\n" "$BLUE" "$YELLOW" "$NC"
}

# ===== Main flow =====
main_install() {
  local success=1

  if [[ "$WANTS_VENV_ONLY" == "true" ]]; then
    create_requirements_if_missing
    setup_venv
    return $?
  fi

  if detect_os; then
    if [[ "$DETECTED_ID" == "arch" || "$DETECTED_ID_LIKE" == *"arch"* ]]; then
      if install_arch; then success=0; fi
    elif [[ "$DETECTED_ID" == "debian" || "$DETECTED_ID_LIKE" == *"debian"* ]]; then
      if install_debian; then success=0; fi
    else
      printf "%b[!] Unsupported OS detected: %s%b\n" "$RED" "$DETECTED_ID" "$NC"
    fi
  else
    printf "%b[!] Could not determine OS%b\n" "$RED" "$NC"
  fi

  # Fallback a venv salvo que se pida lo contrario
  if [[ $success -ne 0 ]]; then
    if [[ "$WANTS_NO_VENV" == "true" ]]; then
      printf "%b[!] System-wide installation failed and --no-venv was set%b\n" "$RED" "$NC"
      return 1
    fi
    printf "%b[!] System-wide installation failed or unsupported OS. Falling back to venv...%b\n" "$YELLOW" "$NC"
    create_requirements_if_missing
    setup_venv || return 1
    success=0
  fi

  return $success
}

show_help() {
  printf "%bJS Exposures Dependency Installer%b\n" "$CYAN" "$NC"
  printf "%bUsage:%b %s [OPTIONS]\n" "$CYAN" "$NC" "$0"
  printf "\n%bOptions:%b\n" "$CYAN" "$NC"
  printf "  %b--venv-only%b   Only set up a Python virtual environment (skip system packages)\n" "$YELLOW" "$NC"
  printf "  %b--check-venv%b  Check if Python venv module is available and exit\n" "$YELLOW" "$NC"
  printf "  %b--no-venv%b     Do not fall back to venv if system install fails; exit with error\n" "$YELLOW" "$NC"
  printf "  %b--help, -h%b    Show this help\n" "$YELLOW" "$NC"
  printf "\nThis script will:\n"
  printf "  1) Try to install system-wide packages via your package manager (Arch/Debian)\n"
  printf "  2) If that fails (or with --venv-only), create a Python virtual environment\n"
  printf "  3) Install dependencies from requirements.txt or minimal set (requests, urllib3)\n"
}

check_venv_only() {
  if check_venv_available; then
    printf "%b[✓] Python venv module is available%b\n" "$GREEN" "$NC"
    exit 0
  else
    printf "%b[!] Python venv module is NOT available%b\n" "$RED" "$NC"
    exit 1
  fi
}

# ===== Arg parsing =====
case "${1:-}" in
  "--venv-only") WANTS_VENV_ONLY="true" ;;
  "--check-venv") check_venv_only ;;
  "--no-venv") WANTS_NO_VENV="true" ;;
  "--help"|"-h") show_help; exit 0 ;;
  "") ;; # no args
  *) printf "%b[!] Unknown option:%b %s\n" "$RED" "$NC" "$1"; show_help; exit 1 ;;
esac

# ===== Banner =====
printf "%b==========================================%b\n" "$CYAN" "$NC"
printf "%b  JS Exposures Dependency Installer%b\n" "$CYAN" "$NC"
printf "%b==========================================%b\n" "$CYAN" "$NC"

# ===== Run =====
create_requirements_if_missing
if main_install; then
  printf "\n%b[✓] Installation completed successfully!%b\n" "$GREEN" "$NC"
  if [[ -f "${VENV_DIR}/bin/activate" ]]; then
    printf "%bTo use the virtual environment:%b\n" "$CYAN" "$NC"
    printf "  %bsource jsexposures_venv/bin/activate%b\n" "$YELLOW" "$NC"
    printf "  %bpython jsexposures.py%b\n" "$YELLOW" "$NC"
    printf "%bTo deactivate later:%b  %bdeactivate%b\n" "$CYAN" "$NC" "$YELLOW" "$NC"
  else
    printf "%bYou can now run:%b  %bpython3 jsexposures.py%b\n" "$CYAN" "$NC" "$YELLOW" "$NC"
  fi
else
  printf "\n%b[!] Installation failed.%b Try: %bpip install requests urllib3%b\n" "$RED" "$NC" "$YELLOW" "$NC"
  exit 1
fi
