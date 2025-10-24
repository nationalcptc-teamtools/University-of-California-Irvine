set -e

if [[ $EUID -ne 0 ]]; then
  echo "must be ran as root"
  exit 1
fi

mkdir -p /opt/bloodhound/
cd /opt/bloodhound/
wget https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-linux-amd64.tar.gz
tar -xvzf bloodhound-cli-linux-amd64.tar.gz
./bloodhound-cli install
