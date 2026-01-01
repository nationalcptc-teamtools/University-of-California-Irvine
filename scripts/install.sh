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
sudo apt install bloodhound-ce-python -y
sudo apt install john -y
sudo apt install hashcat -y
sudo apt install enum4linux-ng -y
sudo apt install proxychains4 -y
sudo apt install python3 -y 
sudo apt install python3-pip -y 
sudo apt install pipx -y
sudo apt install xclip -y
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

