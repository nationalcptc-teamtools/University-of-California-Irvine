#!/usr/bin/env bash
# Sets up Typst Local from a fresh clone.
#
#   ./setup.sh                 install, build, and write .env (then: ./start.sh)
#   ./setup.sh --docker        build and start the Docker container instead
#
# Works on macOS and on Debian-family Linux (Kali, Debian, Ubuntu) from a fresh
# install: Node.js and Rust are downloaded into this folder if missing, and
# build tools are installed with apt (asks first unless -y).
#
# Options:
#   --port N          port to serve on (default 3000)
#   --password PW     access password (default: a random one)
#   --no-password     don't require a password
#   --no-engine       skip building the fast native engine (uses the slower built-in compiler)
#   --service         Linux only: install a systemd service that starts on boot
#   -y, --yes         don't ask before downloading Node.js/Rust or apt-installing build tools
#
# Re-running is safe: existing settings in .env are kept unless you pass new ones.
set -euo pipefail

cd "$(dirname "$0")"
ROOT="$(pwd)"

MODE=native
PORT_ARG=""
PASSWORD_ARG=""
NO_PASSWORD=0
BUILD_ENGINE=1
SERVICE=0
ASSUME_YES=0
MIN_NODE=22
MIN_RUST="1.89"
RUST_TOOLCHAIN="1.92.0"
PANDOC_VERSION="3.12.1"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
info() { printf '  %s\n' "$*"; }
warn() { printf '\033[33m  ! %s\033[0m\n' "$*"; }
die() { printf '\033[31mError: %s\033[0m\n' "$*" >&2; exit 1; }
usage() { sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --docker) MODE=docker ;;
    --port) PORT_ARG="${2:?--port needs a value}"; shift ;;
    --password) PASSWORD_ARG="${2:?--password needs a value}"; shift ;;
    --no-password) NO_PASSWORD=1 ;;
    --no-engine) BUILD_ENGINE=0 ;;
    --service) SERVICE=1 ;;
    -y|--yes) ASSUME_YES=1 ;;
    -h|--help) usage ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
  shift
done

# version_ge A B: is version A >= version B?
version_ge() { [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" == "$2" ]]; }

confirm() {
  [[ $ASSUME_YES -eq 1 ]] && return 0
  [[ -t 0 ]] || return 1
  read -r -p "  $1 [y/N] " reply
  [[ "$reply" =~ ^[Yy] ]]
}

fetch() { # fetch URL OUTPUT
  if command -v curl >/dev/null 2>&1; then curl -fsSL -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then wget -qO "$2" "$1"
  else die "curl or wget is required"; fi
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

SUDO=""
[[ $EUID -ne 0 ]] && SUDO="sudo"

# Installs Debian packages if any of the given commands/packages are missing.
apt_install() {
  command -v apt-get >/dev/null 2>&1 || return 1
  [[ -z "$SUDO" ]] || command -v sudo >/dev/null 2>&1 || return 1
  confirm "Install $* with apt (needs sudo)?" || return 1
  $SUDO apt-get update -qq && DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y -qq "$@" >/dev/null
}

random_password() {
  LC_ALL=C tr -dc 'a-z2-9' </dev/urandom | head -c 16 || true
}

# ---- .env ---------------------------------------------------------------------

env_get() { [[ -f .env ]] && grep -E "^$1=" .env | tail -n1 | cut -d= -f2- || true; }

write_env() {
  local port password
  port="${PORT_ARG:-$(env_get TYPST_LOCAL_PORT)}"
  port="${port:-3000}"
  if [[ $NO_PASSWORD -eq 1 ]]; then
    password=""
  elif [[ -n "$PASSWORD_ARG" ]]; then
    password="$PASSWORD_ARG"
  elif [[ -f .env ]] && grep -qE '^ACCESS_PASSWORD=' .env; then
    password="$(env_get ACCESS_PASSWORD)"
  else
    password="$(random_password)"
  fi
  (
    umask 077
    cat >.env <<EOF
# Typst Local settings, read by the server and by docker compose.
# Port to serve on.
TYPST_LOCAL_PORT=$port
# Password everyone enters once per browser. Leave empty for no password.
ACCESS_PASSWORD=$password
EOF
  )
  FINAL_PORT="$port"
  FINAL_PASSWORD="$password"
}

lan_addresses() {
  if command -v ip >/dev/null 2>&1; then
    ip -4 -o addr show scope global 2>/dev/null | awk '$2 !~ /^(docker|br-|veth|tun|utun|wg)/ {split($4, a, "/"); print a[1]}'
  elif command -v ifconfig >/dev/null 2>&1; then
    ifconfig 2>/dev/null | awk '/^[a-z]/ {iface=$1} /inet / && iface ~ /^en/ {print $2}'
  fi
}

print_access() {
  echo
  bold "Open it at:"
  info "http://localhost:$FINAL_PORT"
  for addr in $(lan_addresses); do info "http://$addr:$FINAL_PORT  (others on your network)"; done
  if [[ -n "$FINAL_PASSWORD" ]]; then
    info "Password: $FINAL_PASSWORD   (change it in .env)"
  else
    warn "No password: anyone who can reach this machine can edit."
  fi
}

# ---- docker mode ----------------------------------------------------------------

if [[ $MODE == docker ]]; then
  bold "Setting up Typst Local with Docker"
  command -v docker >/dev/null 2>&1 || die "Docker is not installed (https://docs.docker.com/get-docker/)."
  docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required (the 'docker compose' command)."
  write_env
  info "Building the image (the first build compiles the Rust engine and takes a few minutes)..."
  docker compose up -d --build
  print_access
  echo
  info "Logs: docker compose logs -f    Stop: docker compose down    Update: git pull && ./setup.sh --docker"
  exit 0
fi

# ---- native mode ------------------------------------------------------------------

bold "Setting up Typst Local"

if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
  apt_install curl ca-certificates || die "curl or wget is required to download Node.js and Rust."
fi

# Node.js: use .node/ if we set it up before, else a recent enough system
# Node, else download the current Node 22 release into .node/.
node_ok() { command -v node >/dev/null 2>&1 && [[ "$(node -p 'process.versions.node.split(".")[0]')" -ge $MIN_NODE ]]; }
if [[ -x .node/bin/node ]]; then
  export PATH="$ROOT/.node/bin:$PATH"
elif ! node_ok; then
  case "$(uname -s)-$(uname -m)" in
    Darwin-arm64) NODE_PLATFORM=darwin-arm64 ;;
    Darwin-x86_64) NODE_PLATFORM=darwin-x64 ;;
    Linux-x86_64) NODE_PLATFORM=linux-x64 ;;
    Linux-aarch64 | Linux-arm64) NODE_PLATFORM=linux-arm64 ;;
    *) die "Node.js $MIN_NODE+ is required; install it from https://nodejs.org" ;;
  esac
  command -v node >/dev/null 2>&1 && info "Found Node.js $(node --version), but $MIN_NODE or newer is needed."
  confirm "Download Node.js $MIN_NODE into this folder (.node/, ~180 MB, doesn't touch your system)?" ||
    die "Node.js $MIN_NODE+ is required. Re-run with -y, or install it from https://nodejs.org"
  NODE_DIST="https://nodejs.org/dist/latest-v$MIN_NODE.x"
  tmp="$(mktemp -d)"
  fetch "$NODE_DIST/SHASUMS256.txt" "$tmp/SHASUMS256.txt"
  NODE_FILE="$(grep -oE "node-v[0-9.]+-$NODE_PLATFORM\.tar\.gz" "$tmp/SHASUMS256.txt" | head -n1)"
  [[ -n "$NODE_FILE" ]] || die "couldn't find a Node.js download for $NODE_PLATFORM"
  info "Downloading $NODE_FILE"
  fetch "$NODE_DIST/$NODE_FILE" "$tmp/$NODE_FILE"
  [[ "$(sha256_of "$tmp/$NODE_FILE")" == "$(grep " $NODE_FILE\$" "$tmp/SHASUMS256.txt" | awk '{print $1}')" ]] ||
    die "checksum mismatch for $NODE_FILE"
  rm -rf .node && mkdir -p .node
  tar -xzf "$tmp/$NODE_FILE" -C .node --strip-components=1
  rm -rf "$tmp"
  export PATH="$ROOT/.node/bin:$PATH"
fi
NODE_BIN="$(command -v node)"
info "Node.js $(node --version) ($NODE_BIN)"

command -v git >/dev/null 2>&1 || apt_install git || warn "git not found: version history won't be mirrored to git repositories."

bold "Installing dependencies"
if [[ -f package-lock.json ]]; then npm ci --no-audit --no-fund; else npm install --no-audit --no-fund; fi

bold "Building the web client"
node build.mjs

ENGINE_STATUS="not built (using the slower built-in compiler)"
if [[ $BUILD_ENGINE -eq 1 ]]; then
  bold "Building the fast compile engine"
  CARGO=""
  if [[ -x .rust/cargo/bin/cargo ]]; then
    export RUSTUP_HOME="$ROOT/.rust/rustup" CARGO_HOME="$ROOT/.rust/cargo"
    CARGO=".rust/cargo/bin/cargo"
  elif command -v cargo >/dev/null 2>&1 && command -v rustc >/dev/null 2>&1; then
    RUSTC_VERSION="$(rustc --version | awk '{print $2}')"
    if version_ge "$RUSTC_VERSION" "$MIN_RUST"; then
      CARGO="cargo"
    else
      info "Your Rust is $RUSTC_VERSION; the engine needs $MIN_RUST or newer."
    fi
  fi

  if [[ -z "$CARGO" ]]; then
    case "$(uname -s)-$(uname -m)" in
      Darwin-arm64) TRIPLE=aarch64-apple-darwin ;;
      Darwin-x86_64) TRIPLE=x86_64-apple-darwin ;;
      Linux-x86_64) TRIPLE=x86_64-unknown-linux-gnu ;;
      Linux-aarch64 | Linux-arm64) TRIPLE=aarch64-unknown-linux-gnu ;;
      *) TRIPLE="" ;;
    esac
    command -v curl >/dev/null 2>&1 || apt_install curl ca-certificates || true
    if [[ -n "$TRIPLE" ]] && command -v curl >/dev/null 2>&1 && confirm "Install Rust $RUST_TOOLCHAIN inside this folder (.rust/, ~400 MB, doesn't touch your system)?"; then
      mkdir -p .rust
      fetch "https://static.rust-lang.org/rustup/dist/$TRIPLE/rustup-init" .rust/rustup-init
      chmod +x .rust/rustup-init
      export RUSTUP_HOME="$ROOT/.rust/rustup" CARGO_HOME="$ROOT/.rust/cargo"
      .rust/rustup-init -y --no-modify-path --profile minimal --default-toolchain "$RUST_TOOLCHAIN" >/dev/null
      CARGO=".rust/cargo/bin/cargo"
    fi
  fi

  if [[ -n "$CARGO" ]]; then
    # Linux builds need a C toolchain and OpenSSL headers (for package downloads).
    if [[ "$(uname -s)" == Linux ]]; then
      if ! command -v cc >/dev/null 2>&1 || ! { command -v pkg-config >/dev/null 2>&1 && pkg-config --exists openssl; }; then
        apt_install build-essential pkg-config libssl-dev ||
          warn "Missing build tools; if the build fails install a C compiler, pkg-config and OpenSSL headers."
      fi
    fi
    if node scripts/build-engine.mjs; then
      ENGINE_STATUS="built (bin/typst-engine)"
    else
      warn "The engine failed to build; the server will use the slower built-in compiler."
    fi
  else
    warn "Skipping the engine; the server will use the slower built-in compiler. Re-run with -y to install Rust locally."
  fi
fi

# pandoc converts documents to Word (.docx). Uses a system pandoc if present,
# else downloads the official build into .pandoc/.
bold "Word export (pandoc)"
if [[ -x .pandoc/bin/pandoc ]]; then
  info "pandoc $(.pandoc/bin/pandoc --version | head -n1 | awk '{print $2}') (.pandoc/)"
elif command -v pandoc >/dev/null 2>&1; then
  info "pandoc $(pandoc --version | head -n1 | awk '{print $2}') (system)"
else
  case "$(uname -s)-$(uname -m)" in
    Darwin-arm64) PANDOC_FILE="pandoc-$PANDOC_VERSION-arm64-macOS.zip" ;;
    Darwin-x86_64) PANDOC_FILE="pandoc-$PANDOC_VERSION-x86_64-macOS.zip" ;;
    Linux-x86_64) PANDOC_FILE="pandoc-$PANDOC_VERSION-linux-amd64.tar.gz" ;;
    Linux-aarch64 | Linux-arm64) PANDOC_FILE="pandoc-$PANDOC_VERSION-linux-arm64.tar.gz" ;;
    *) PANDOC_FILE="" ;;
  esac
  if [[ -n "$PANDOC_FILE" ]] && confirm "Download pandoc $PANDOC_VERSION into this folder (.pandoc/, ~200 MB) for Word export?"; then
    tmp="$(mktemp -d)"
    if fetch "https://github.com/jgm/pandoc/releases/download/$PANDOC_VERSION/$PANDOC_FILE" "$tmp/$PANDOC_FILE"; then
      case "$PANDOC_FILE" in
        *.zip) (cd "$tmp" && unzip -q "$PANDOC_FILE") ;;
        *) tar -xzf "$tmp/$PANDOC_FILE" -C "$tmp" ;;
      esac
      found="$(find "$tmp" -type f -path '*/bin/pandoc' | head -n1)"
      if [[ -n "$found" ]]; then
        mkdir -p .pandoc/bin && cp "$found" .pandoc/bin/pandoc && chmod +x .pandoc/bin/pandoc
        info "pandoc $PANDOC_VERSION installed in .pandoc/"
      fi
    fi
    rm -rf "$tmp"
  fi
  [[ -x .pandoc/bin/pandoc ]] || warn "No pandoc: Download → Word won't work (everything else does)."
fi

bold "Writing settings"
write_env
info ".env (port $FINAL_PORT, $([[ -n "$FINAL_PASSWORD" ]] && echo "password set" || echo "no password"))"
mkdir -p data/fonts

if [[ $SERVICE -eq 1 ]]; then
  bold "Installing systemd service"
  [[ "$(uname -s)" == Linux ]] && command -v systemctl >/dev/null 2>&1 || die "--service needs Linux with systemd."
  RUN_USER="$(id -un)"
  $SUDO tee /etc/systemd/system/typst-local.service >/dev/null <<EOF
[Unit]
Description=Typst Local collaborative editor
After=network-online.target
Wants=network-online.target

[Service]
User=$RUN_USER
WorkingDirectory=$ROOT
ExecStart=$NODE_BIN $ROOT/server/index.js
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
  $SUDO systemctl daemon-reload
  $SUDO systemctl enable --now typst-local
  $SUDO systemctl restart typst-local
  info "Running as service 'typst-local' (logs: journalctl -u typst-local -f)"
fi

echo
bold "Done. Engine: $ENGINE_STATUS"
if [[ $SERVICE -eq 0 ]]; then
  echo
  bold "Start the server with:"
  info "./start.sh"
fi
print_access
