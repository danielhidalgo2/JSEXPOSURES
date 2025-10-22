#!/bin/bash

# Global variables for OS detection
DETECTED_ID=""
DETECTED_ID_LIKE=""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to detect OS
detect_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        DETECTED_ID="$ID"
        DETECTED_ID_LIKE="$ID_LIKE"
        return 0
    else
        echo -e "${RED}[!] Could not determine OS via /etc/os-release${NC}"
        return 1
    fi
}

# Function to check if venv is available
check_venv_available() {
    echo -e "${BLUE}[+] Checking if Python virtual environment module is available...${NC}"
    
    if python3 -c "import venv" 2>/dev/null; then
        echo -e "${GREEN}[✓] Python venv module is available${NC}"
        return 0
    else
        echo -e "${RED}[!] Python venv module is not available${NC}"
        return 1
    fi
}

# Function to install venv on Arch-based systems
install_venv_arch() {
    echo -e "${BLUE}[+] Installing python-venv on Arch-based system...${NC}"
    if sudo pacman -Sy --noconfirm python-virtualenv || sudo pacman -Sy --noconfirm python-venv; then
        echo -e "${GREEN}[✓] python-virtualenv installed successfully${NC}"
        return 0
    else
        # Try installing with pip as fallback
        if python3 -m pip install virtualenv; then
            echo -e "${GREEN}[✓] virtualenv installed via pip${NC}"
            return 0
        else
            echo -e "${RED}[!] Failed to install virtualenv${NC}"
            return 1
        fi
    fi
}

# Function to install venv on Debian-based systems
install_venv_debian() {
    echo -e "${BLUE}[+] Installing python3-venv on Debian-based system...${NC}"
    sudo apt update
    if sudo apt install -y python3-venv python3-virtualenv; then
        echo -e "${GREEN}[✓] python3-venv installed successfully${NC}"
        return 0
    else
        # Try installing with pip as fallback
        if python3 -m pip install virtualenv; then
            echo -e "${GREEN}[✓] virtualenv installed via pip${NC}"
            return 0
        else
            echo -e "${RED}[!] Failed to install virtualenv${NC}"
            return 1
        fi
    fi
}

# Function to install system-wide dependencies on Arch-based systems
install_arch() {
    echo -e "${BLUE}[+] Arch based OS detected, installing via pacman...${NC}"
    if sudo pacman -Sy python-requests python-urllib3; then
        echo -e "${BLUE}[+] Dependency install finished${NC}"
        return 0
    else
        echo -e "${RED}[!] Failed to install dependencies via pacman${NC}"
        return 1
    fi
}

# Function to install system-wide dependencies on Debian-based systems
install_debian() {
    echo -e "${BLUE}[+] Debian based OS detected, installing via apt...${NC}"
    sudo apt update
    if sudo apt install -y python3-requests python3-urllib3; then
        echo -e "${BLUE}[+] Dependency install finished${NC}"
        return 0
    else
        echo -e "${RED}[!] Failed to install dependencies via apt${NC}"
        return 1
    fi
}

# Function to setup virtual environment with venv availability check
setup_venv() {
    echo -e "${BLUE}[+] Setting up Python virtual environment...${NC}"
    
    # Check if python3 is available
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}[!] Python3 is not installed. Please install Python3 first.${NC}"
        return 1
    fi
    
    # Check if venv is available
    if ! check_venv_available; then
        echo -e "${RED}[!] Python venv module is not available. Attempting to install it...${NC}"
        
        detect_os
        local venv_installed=1
        
        if [[ "$DETECTED_ID" == "arch" || "$DETECTED_ID_LIKE" == *"arch"* ]]; then
            install_venv_arch
            venv_installed=$?
        elif [[ "$DETECTED_ID" == "debian" || "$DETECTED_ID_LIKE" == *"debian"* ]]; then
            install_venv_debian
            venv_installed=$?
        else
            echo -e "${RED}[!] Unsupported OS for automatic venv installation${NC}"
            echo -e "${BLUE}[+] Trying to install virtualenv via pip as fallback...${NC}"
            if python3 -m pip install virtualenv; then
                venv_installed=0
            fi
        fi
        
        if [[ $venv_installed -ne 0 ]]; then
            echo -e "${RED}[!] Could not install virtualenv. Please install it manually:${NC}"
            echo -e "${YELLOW}     Debian/Ubuntu: sudo apt install python3-venv${NC}"
            echo -e "${YELLOW}     Arch: sudo pacman -S python-virtualenv${NC}"
            echo -e "${YELLOW}     Or via pip: python3 -m pip install virtualenv${NC}"
            return 1
        fi
        
        # Verify venv is now available
        if ! check_venv_available; then
            echo -e "${RED}[!] venv still not available after installation attempt${NC}"
            return 1
        fi
    fi
    
    # Create virtual environment
    echo -e "${BLUE}[+] Creating virtual environment...${NC}"
    if python3 -m venv jsexposures_venv; then
        echo -e "${GREEN}[✓] Virtual environment created successfully${NC}"
    else
        echo -e "${RED}[!] Failed to create virtual environment with venv${NC}"
        echo -e "${BLUE}[+] Trying alternative method with virtualenv...${NC}"
        if python3 -m virtualenv jsexposures_venv; then
            echo -e "${GREEN}[✓] Virtual environment created with virtualenv${NC}"
        else
            echo -e "${RED}[!] Failed to create virtual environment${NC}"
            return 1
        fi
    fi
    
    # Activate virtual environment
    source jsexposures_venv/bin/activate
    
    # Upgrade pip first
    echo -e "${BLUE}[+] Upgrading pip...${NC}"
    pip install --upgrade pip
    
    # Check if requirements.txt exists
    if [[ -f "requirements.txt" ]]; then
        echo -e "${BLUE}[+] Installing dependencies from requirements.txt...${NC}"
        pip install -r requirements.txt
    else
        echo -e "${BLUE}[+] requirements.txt not found, installing basic dependencies...${NC}"
        pip install requests urllib3
        # Create requirements file for future use
        pip freeze > requirements.txt
        echo -e "${BLUE}[+] Created requirements.txt with current dependencies${NC}"
    fi
    
    echo -e "${GREEN}[✓] Virtual environment setup completed!${NC}"
    echo -e "${BLUE}[+] To activate the venv in the future run: "${YELLOW}"source jsexposures_venv/bin/activate${NC}"
    return 0
}

# Function to ask for virtual environment setup
ask_for_venv() {
    echo
    read -p -e "${MAGENTA}[?] Do you want to create a Python virtual environment and install dependencies there? (y/n): ${NC}" -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        setup_venv
        return $?
    else
        echo -e "${RED}[!] Skipping virtual environment setup.${NC}"
        echo -e "${RED}[!] You can manually install dependencies with: pip install requests urllib3${NC}"
        return 1
    fi
}

# Main installation function
main_install() {
    local success=1
    
    # Detect OS first
    if detect_os; then
        if [[ "$DETECTED_ID" == "arch" || "$DETECTED_ID_LIKE" == *"arch"* ]]; then
            if install_arch; then
                success=0
            fi
        elif [[ "$DETECTED_ID" == "debian" || "$DETECTED_ID_LIKE" == *"debian"* ]]; then
            if install_debian; then
                success=0
            fi
        else
            echo -e "${RED}[!] Unsupported OS detected: $DETECTED_ID${NC}"
        fi
    else
        echo -e "${RED}[!] Could not determine OS${NC}"
    fi

    # If system-wide install failed or OS not detected, offer venv option
    if [[ $success -ne 0 ]]; then
        echo
        echo -e "${RED}[!] System-wide installation failed or OS not supported.${NC}"
        ask_for_venv
        success=$?
    fi
    
    return $success
}

# Create a basic requirements.txt if it doesn't exist
create_requirements_if_missing() {
    if [[ ! -f "requirements.txt" ]]; then
        cat > requirements.txt << EOF
requests>=2.28.0
urllib3>=1.26.0
EOF
        echo -e "${BLUE}[+] Created requirements.txt with basic dependencies${NC}"
    fi
}

# Display help information
show_help() {
    echo -e "${CYAN}JS Exposures Dependency Installer${NC}"
    echo -e "${CYAN}Usage: $0 [OPTIONS]${NC}"
    echo
    echo -e "${CYAN}Options:${NC}"
    echo -e "  ${YELLOW}--venv-only    Skip system package manager and only setup virtual environment${NC}"
    echo -e "  ${YELLOW}--check-venv   Check if venv is available without installing${NC}"
    echo -e "  ${YELLOW}--help         Show this help message${NC}"
    echo
    echo -e "${CYAN}This script will:${NC}"
    echo -e "  1. Try to install system-wide packages via your package manager"
    echo -e "  2. If that fails, offer to create a Python virtual environment"
    echo -e "  3. Install dependencies in the virtual environment"
    echo -e "  4. Automatically install venv if not available"
}

# Check only venv availability
check_venv_only() {
    if check_venv_available; then
        echo -e "${GREEN}[✓] venv is available and ready to use${NC}"
        return 0
    else
        echo -e "${RED}[!] venv is not available${NC}"
        return 1
    fi
}

# Parse command line arguments
case "${1:-}" in
    "--venv-only")
        create_requirements_if_missing
        setup_venv
        exit $?
        ;;
    "--check-venv")
        check_venv_only
        exit $?
        ;;
    "--help"|"-h")
        show_help
        exit 0
        ;;
    "")
        # No arguments, proceed with normal flow
        ;;
    *)
        echo -e "${RED}[!] Unknown option: $1${NC}"
        echo -e "${YELLOW}Use --help for usage information${NC}"
        exit 1
        ;;
esac

# Welcome message
echo -e "${CYAN}==========================================${NC}"
echo -e "${CYAN}  JS Exposures Dependency Installer${NC}"
echo -e "${CYAN}==========================================${NC}"

# Create requirements.txt if missing
create_requirements_if_missing

# Run main installation
if main_install; then
    echo
    echo -e "${GREEN}[✓] Installation completed successfully!${NC}"
    echo
    if [[ -f "jsexposures_venv/bin/activate" ]]; then
        echo -e "${CYAN}To use the virtual environment:${NC}"
        echo -e "  ${YELLOW}source jsexposures_venv/bin/activate${NC}"
        echo -e "  ${YELLOW}python jsexposures.py${NC}"
        echo
        echo -e "${CYAN}To deactivate the virtual environment later:${NC}"
        echo -e "  ${YELLOW}deactivate${NC}"
    else
        echo -e "${CYAN}You can now run: python jsexposures.py${NC}"
    fi
else
    echo
    echo -e "${RED}[!] Installation failed. You may need to manually install dependencies.${NC}"
    echo -e "${YELLOW}Try: pip install requests urllib3${NC}"
    exit 1
fi