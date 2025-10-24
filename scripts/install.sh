#!/bin/env bash

set -e

if [[ $EUID -ne 0 ]]; then
  echo "must be ran as root"
  exit 1
fi

sudo wget https://archive.kali.org/archive-keyring.gpg -O /usr/share/keyrings/kali-archive-keyring.gpg
sudo apt update -y 

sudo apt install hashid -y
sudo apt install hash-identifier -y
sudo apt install bloodhound.py -y
sudo apt install john -y
sudo apt install hashcat -y
sudo apt install enum4linux-ng -y
sudo apt install proxychains4 -y
sudo apt install python3 -y 
sudo apt install python3-pip -y 
sudo apt install pipx -y
pipx ensurepath
sudo pipx ensurepath --global 
pipx install bloodyAD
pipx install uv
sudo apt install git -y 
sudo apt install wget -y 
sudo apt install curl -y 
sudo apt install nmap -y 
sudo apt install vim -y 
sudo apt install nano -y 
sudo apt install tmux -y 
sudo apt install flameshot -y
sudo apt install python3-venv -y 
sudo apt install wordlists -y
sudo apt install seclists -y
sudo apt install impacket-scripts -y
sudo apt install ligolo-ng -y
sudo apt install hydra -y
sudo apt install gobuster -y
sudo apt install ffuf -y
sudo apt install sqlmap -y
sudo apt install netexec -y
sudo apt install docker.io -y
sudo apt install docker-compose -y



sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up


#TMUX SETUP
TARGET_USER="${SUDO_USER:-$USER}"
USER_HOME=$(eval echo ~${SUDO_USER:-$USER})
sudo -u "$TARGET_USER" -H git clone https://github.com/tmux-plugins/tpm "$USER_HOME/.tmux/plugins/tpm"
sudo -u "$TARGET_USER" -H mkdir -p $USER_HOME/tmux-logs

sudo -u "$TARGET_USER" -H bash <<EOF
cat > "\$HOME/.tmux.conf" <<EOC
set -g @plugin 'tmux-plugins/tpm'
set -g @plugin 'tmux-plugins/tmux-sensible'
set -g @plugin 'tmux-plugins/tmux-logging'
set -g @logging-path "\$HOME/tmux-logs"

run -b '~/.tmux/plugins/tpm/tpm'
EOC
EOF

sudo -u "$TARGET_USER" -H tmux new-session -d -s _tpm_bootstrap
sleep 0.5
sudo -u "$TARGET_USER" -H tmux send-keys -t _tpm_bootstrap "tmux source-file $USER_HOME/.tmux.conf" C-m
sleep 0.5
sudo -u "$TARGET_USER" -H tmux send-keys -t _tpm_bootstrap "$USER_HOME/.tmux/plugins/tpm/bin/install_plugins" C-m
sleep 1
sudo -u "$TARGET_USER" -H tmux send-keys -t _tpm_bootstrap C-b I
sleep 1

sudo -u "$TARGET_USER" -H tmux kill-session -t _tpm_bootstrap
