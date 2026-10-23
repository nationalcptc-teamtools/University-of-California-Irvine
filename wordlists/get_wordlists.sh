#!/bin/bash
#
# Fetch the wordlists we use into this directory. Written for Kali.
#
# rockyou comes from the box when it can: Kali already ships it (gzipped until first
# use), so we copy that instead of pulling 139 MB we already have. If it is not there,
# we download it. Set ROCKYOU_SRC if it lives somewhere else on your box.
#
# Safe to re-run: anything already here is left alone.
set -euo pipefail

# The script lives in the wordlists directory, so work there no matter where it is
# called from - the old version did "mkdir wordlists; cd wordlists" and, run from its
# own directory, built wordlists/wordlists.
cd -- "$(cd -- "$(dirname -- "$0")" && pwd)"

ROCKYOU_SRC="${ROCKYOU_SRC:-/usr/share/wordlists/rockyou.txt}"
# Only used when the box has no copy. Override if weakpass is blocked or moves.
ROCKYOU_URL="${ROCKYOU_URL:-https://weakpass.com/download/90/rockyou.txt.gz}"

get() {      # get <url> [filename]  - the second form is for lists SecLists has renamed
    local url="$1" name
    name="${2:-$(basename "$url")}"
    if [[ -s $name ]]; then
        printf '[=] %s already here\n' "$name"
        return
    fi
    printf '[*] %s\n' "$name"
    wget -q --show-progress -O "$name.part" "$url" || { rm -f -- "$name.part"; return 1; }
    mv -- "$name.part" "$name"
}

get https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/combined_directories.txt
get https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/big.txt
get https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/burp-parameter-names.txt
get https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/2023-200_most_used_passwords.txt
get https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/refs/heads/master/Command%20Injection/Intruder/command-execution-unix.txt
get https://raw.githubusercontent.com/danielmiessler/SecLists/e3a840b672fe193bafe45fbfe6eb20c8f6e15c2f/Discovery/DNS/bitquark-subdomains-top100000.txt
get https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/DNS/combined_subdomains.txt

# SecLists renamed this one to DirBuster-2007_directory-list-2.3-small.txt; keep the old
# filename, which is what everything here already refers to.
get https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt directory-list-2.3-small.txt

# API endpoints: api-seen-in-wild.txt is 7,600-odd paths observed in the real world, and
# api-endpoints.txt is a short curated list of endpoint names. Discovery/Web-Content/api/
# also has objects.txt (3,100 object and parameter names) if you want that too.
get https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/api/api-seen-in-wild.txt
get https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/api/api-endpoints.txt

# Assetnote's swagger wordlist: 958,872 endpoint paths pulled out of real Swagger and
# OpenAPI definitions, 27 MB. Thorough but slow to fuzz with directly - it is the
# wordlist behind kiterunner, which replays whole request schemas instead of guessing
# paths. Use api-endpoints.txt or api-seen-in-wild.txt for a first pass and this when
# you want depth.
get https://wordlists-cdn.assetnote.io/data/kiterunner/swagger-wordlist.txt

# rockyou: copy the one Kali gave us, decompressing if it has not been used yet. The
# system copy is left as it is, so /usr/share/wordlists/rockyou.txt keeps working for
# anything that points at it (autoWin.py does).
if [[ -s rockyou.txt ]]; then
    printf '[=] rockyou.txt already here\n'
elif [[ -s $ROCKYOU_SRC ]]; then
    printf '[*] rockyou.txt <- %s\n' "$ROCKYOU_SRC"
    cp -- "$ROCKYOU_SRC" rockyou.txt
elif [[ -s $ROCKYOU_SRC.gz ]]; then
    printf '[*] rockyou.txt <- %s.gz (decompressing a copy)\n' "$ROCKYOU_SRC"
    gunzip -c -- "$ROCKYOU_SRC.gz" > rockyou.txt
else
    printf '[*] rockyou.txt not on this box (%s), downloading 139 MB\n' "$ROCKYOU_SRC"
    wget -q --show-progress -O rockyou.txt.gz "$ROCKYOU_URL"
    gunzip -- rockyou.txt.gz
fi

# Everything on the list should now be here, and non-empty.
missing=0
for f in rockyou.txt combined_directories.txt big.txt burp-parameter-names.txt \
         2023-200_most_used_passwords.txt command-execution-unix.txt \
         bitquark-subdomains-top100000.txt combined_subdomains.txt \
         directory-list-2.3-small.txt api-seen-in-wild.txt api-endpoints.txt \
         swagger-wordlist.txt; do
    if [[ -s $f ]]; then
        printf '    %-34s %s\n' "$f" "$(du -h -- "$f" | cut -f1)"
    else
        printf '[!] %-34s MISSING\n' "$f" >&2
        missing=$((missing + 1))
    fi
done
[[ $missing -eq 0 ]] || { printf '[!] %d wordlist(s) missing\n' "$missing" >&2; exit 1; }

printf '[+] done, in %s\n' "$PWD"
