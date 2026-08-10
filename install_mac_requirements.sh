#!/usr/bin/env bash

# Colors
GREEN="\033[1;32m"
RED="\033[1;31m"
NC="\033[0m"

echo -e "\n📦 Installing Requirements for macOS...\n"

function check_install() {
    if command -v "$1" &>/dev/null; then
        echo -e "✅ $1 is already installed"
    else
        echo -e "❌ $1 not found. Installing..."
        brew install "$2" && echo -e "${GREEN}✔ Installed: $2${NC}" || echo -e "${RED}✘ Failed to install: $2${NC}"
    fi
}

# Check for Homebrew
if ! command -v brew &>/dev/null; then
    echo -e "${RED}Homebrew not found. Please install Homebrew first: https://brew.sh${NC}"
    exit 1
fi

check_install "jq" "jq"
check_install "lolcat" "lolcat"
check_install "figlet" "figlet"
check_install "wget" "wget"
check_install "gum" "gum" # gum is available via Homebrew

echo -e "\n${GREEN}🎉 All requirements checked and installed!${NC}\n"
