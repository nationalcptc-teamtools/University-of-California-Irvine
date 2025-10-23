#!/bin/env bash

set -e

if [[ $EUID -ne 0 ]]; then
  echo "must be ran as root"
  exit 1
fi

sudo apt update -y 
sudo apt install -y \
    git \
    wget \
    curl \
    nmap \
    pipx \
    john \
    hashcat \
    vim \
    nano \
    tmux \
    flameshot \
    python3 \
    python3-pip \
    python3-venv \
    wordlists \
    seclists \
    impacket-scripts \
    ligolo-ng \
    hydra \
    gobuster \
    ffuf \
    sqlmap \
    netexec \
    docker.io \
    docker-compose

systemctl enable docker --now
docker pull neo4j:latest
docker run -d \
    --name neo4j \
    -p 7474:7474 \
    -p 7687:7687 \
    -e NEO4J_AUTH="neo4j/neo4j" \
    -v neo4j_data:/data \
    --restart unless-stopped \
    neo4j:latest
docker pull bloodhoundad/bloodhound:latest
docker run -d \
    --name bloodhound \
    -p "8080:8080"
    -e BLOODHOUND_NEO4J_URI="bolt://neo4j:neo4j@neo4j:7687" \
    --link neo4j \
    --restart unless-stopped \
    bloodhoundad/bloodhound:latest

sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up

