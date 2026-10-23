#!/bin/env bash
#
# Cyber@UCI CPTC attack-box setup. Run as root on a Kali box.
#
# No `set -e`: if one tool fails to install we want the other 29 to finish, not
# have the whole script die. Every step runs through run(), which records any
# failure and prints the list at the end, so nothing fails silently.

if [[ $EUID -ne 0 ]]; then
  echo "must be ran as root"
  exit 1
fi

FAILED=()
run() { echo "[*] $*"; "$@" || FAILED+=("$*"); }

# autowin lives one directory up from setup/; resolve it relative to this
# script so the install works no matter where the script is invoked from.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUTOWIN_SRC="$SCRIPT_DIR/../autowin"

run wget https://archive.kali.org/archive-keyring.gpg -O /usr/share/keyrings/kali-archive-keyring.gpg
run apt update -y

# Build toolchain, installed before the pipx block that needs it: pipx builds
# NetExec's netifaces/arc4 deps from source on Kali's current python (no
# prebuilt wheels for it), which needs gcc (build-essential) and Python.h
# (python3-dev). Without these the NetExec install fails.
run apt install -y build-essential python3-dev

run apt install -y hashid
run apt install -y hash-identifier
run apt install -y bloodhound.py
run apt install -y bloodhound-ce-python
run apt install -y john
run apt install -y hashcat
run apt install -y enum4linux-ng
run apt install -y proxychains4
run apt install -y pipx
run apt install -y xclip
run pipx ensurepath
run pipx ensurepath --global
run pipx install bloodyAD
run pipx install uv
run pipx install git+https://github.com/Pennyw0rth/NetExec
run pipx install penelope-shell-handler
# autowin: AD enumeration/discovery tool from this repo -> `autowin` on PATH
run pipx install "$AUTOWIN_SRC"
run apt install -y git
run apt install -y wget
run apt install -y curl
run apt install -y nmap
run apt install -y vim
run apt install -y nano
run apt install -y tmux
run apt install -y flameshot
run apt install -y python3
run apt install -y python3-pip
run apt install -y python3-venv
run apt install -y python3-venv \
  wordlists \
  seclists \
  impacket-scripts \
  ligolo-ng \
  hydra \
  gobuster \
  feroxbuster \
  ffuf \
  sqlmap

# ligolo tun. Guarded so a re-run does not fail on an interface that already
# exists.
ip link show ligolo >/dev/null 2>&1 || run ip tuntap add user kali mode tun ligolo
run ip link set ligolo up

if ((${#FAILED[@]})); then
  printf '\n!! %d step(s) FAILED:\n' "${#FAILED[@]}"
  printf '   %s\n' "${FAILED[@]}"
  exit 1
fi
printf '\n[+] all steps completed\n'
