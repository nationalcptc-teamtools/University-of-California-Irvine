#!/usr/bin/env bash

set -u -o pipefail

# Usage function
usage() {
  cat << EOF
Usage: $0 <target-ip> <service> <user|user-list> <password|password-list> [port] [error-message]

Services supported:
  ssh, ftp, http-get, http-post, rdp, mysql, postgresql, mongodb, smb, telnet, vnc

Arguments:
  target-ip       : Target IP address or hostname
  service         : Service to attack (see supported services above)
  user            : Single username OR path to user list file
  password        : Single password OR path to password list file
  port            : (Optional) Custom port number
  error-message   : (Optional) Error message for http services (e.g., "Invalid" or "Login failed")

Examples:
  $0 10.0.0.5 ssh admin passwords.txt
  $0 10.0.0.5 ssh users.txt passwords.txt
  $0 10.0.0.5 http-post admin passwords.txt 8080 "Invalid credentials"
  $0 10.0.0.5 mysql root rockyou.txt
  $0 192.168.1.10 rdp administrator passwords.txt 3389

EOF
  exit 1
}


if [[ $# -lt 4 ]]; then
  usage
fi

target="$1"
service="$2"
user_input="$3"
pass_input="$4"
custom_port="${5:-}"
error_msg="${6:-}"

if [[ -f "$user_input" ]]; then
  user_flag="-L"
  user_value="$user_input"
else
  user_flag="-l"
  user_value="$user_input"
fi

if [[ -f "$pass_input" ]]; then
  pass_flag="-P"
  pass_value="$pass_input"
else
  pass_flag="-p"
  pass_value="$pass_input"
fi

# Default ports (So you dont have to specify)
declare -A default_ports=(
  ["ssh"]="22"
  ["ftp"]="21"
  ["http-get"]="80"
  ["http-post"]="80"
  ["rdp"]="3389"
  ["mysql"]="3306"
  ["postgresql"]="5432"
  ["mongodb"]="27017"
  ["smb"]="445"
  ["telnet"]="23"
  ["vnc"]="5900"
)


if [[ -n "$custom_port" ]]; then
  port="$custom_port"
elif [[ -n "${default_ports[$service]:-}" ]]; then
  port="${default_ports[$service]}"
else
  echo "Unknown service: $service"
  usage
fi


hydra_cmd="hydra -V -f $user_flag \"$user_value\" $pass_flag \"$pass_value\""


case "$service" in
  ssh|ftp|telnet|smb|vnc|mysql|postgresql|mongodb)
    hydra_cmd="$hydra_cmd -s $port $target $service"
    ;;
  
  rdp)
    hydra_cmd="$hydra_cmd -s $port $target rdp"
    ;;
  
  http-get)
    if [[ -n "$error_msg" ]]; then
      hydra_cmd="$hydra_cmd -s $port $target http-get / -e nsr -F -V -t 4 -w 10 -o hydra_http_get.txt -b \"$error_msg\""
    else
      hydra_cmd="$hydra_cmd -s $port $target http-get /"
    fi
    ;;
  
  http-post)
    if [[ -n "$error_msg" ]]; then
      hydra_cmd="$hydra_cmd -s $port $target http-post-form \"/login:username=^USER^&password=^PASS^:$error_msg\" -V -t 4"
    else
      echo "Error: http-post requires an error message parameter"
      echo "Example: $0 $target http-post $user_input $pass_input $port 'Invalid credentials'"
      exit 1
    fi
    ;;
  
  *)
    echo "Unsupported service: $service"
    usage
    ;;
esac


echo "=========================================="
echo "Warning: Make sure to not get locked out due to brute forcing. Only run if you know the lockout policy, if one exists"
echo "Target: $target"
echo "Service: $service"
echo "Port: $port"
echo "User(s): $user_input"
echo "Password(s): $pass_input"
[[ -n "$error_msg" ]] && echo "Error Message: $error_msg"
echo "=========================================="
echo
echo "Running: $hydra_cmd"
echo
echo "=========================================="
echo


eval "$hydra_cmd"

exit_code=$?

echo
echo "=========================================="
if [[ $exit_code -eq 0 ]]; then
  echo "✓ Hydra completed successfully!"
  echo "Check output above for valid credentials"
else
  echo "Hydra finished with errors or no valid credentials found"
fi
echo "=========================================="

exit $exit_code
