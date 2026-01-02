#!/bin/bash
mkdir wordlists
cd wordlists
wget https://weakpass.com/download/90/rockyou.txt.gz
wget https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/combined_directories.txt
wget https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/2023-200_most_used_passwords.txt
wget https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/burp-parameter-names.txt
wget https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/refs/heads/master/Command%20Injection/Intruder/command-execution-unix.txt
wget https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/big.txt
wget https://raw.githubusercontent.com/danielmiessler/SecLists/e3a840b672fe193bafe45fbfe6eb20c8f6e15c2f/Discovery/DNS/bitquark-subdomains-top100000.txt
gunzip rockyou.txt.gz
