#!/bin/env bash

set -e

if [[ $EUID -ne 0 ]]; then
  echo "must be ran as root"
  exit 1
fi

sudo apt install docker.io docker-compose -y
wget https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-linux-amd64.tar.gz
tar xvf ./bloodhound-cli-linux-amd64.tar.gz
./bloodhound-cli install
