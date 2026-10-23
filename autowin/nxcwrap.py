"""Thin subprocess wrapper around NetExec + parsers for its text output.

We deliberately drive the `nxc` binary rather than importing the library, so
autowin-new stays robust across NetExec versions.
"""
import re
import socket
from dataclasses import dataclass

from shell import run
from schema import User

# PROTO  IP  PORT  HOSTNAME  <rest>
HOST_LINE = re.compile(r'^(SMB|LDAP|WINRM|MSSQL|RDP|SSH|FTP|WMI)\s+(\S+)\s+(\d+)\s+(\S+)\s+(.*)$')

_BANNER_NAME = re.compile(r'\(name:([^)]*)\)')
_BANNER_DOMAIN = re.compile(r'\(domain:([^)]*)\)')
_BANNER_SIGNING = re.compile(r'\(signing:(True|False)\)')
_BANNER_SMBV1 = re.compile(r'\(SMBv1:(True|False)\)')
_RID_LINE = re.compile(r'(\d+):\s+([^\\]+)\\([^\s]+)\s+\(SidType(\w+)\)')


@dataclass
class Cred:
    username: str
    secret: str
    domain: str | None = None
    is_hash: bool = False
    kerberos: bool = False

    @classmethod
    def anonymous(cls) -> 'Cred':
        return cls(username='', secret='')

    @classmethod
    def guest(cls) -> 'Cred':
        return cls(username='guest', secret='')

    @classmethod
    def from_user(cls, user: User) -> 'Cred':
        if user.password is not None:
            return cls(user.name, user.password, user.domain.name)
        if user.hash is not None and user.hash.source == 'ntlm':
            return cls(user.name, user.hash.hash, user.domain.name, is_hash=True)
        raise ValueError(f'user {user.name} has no usable credential')

    def label(self) -> str:
        if not self.username:
            return 'anonymous'
        return f'{self.username}:{self.secret}' if self.secret else f'{self.username}:'

    def key(self) -> str:
        """Stable identity for resume bookkeeping (which context ran a step)."""
        return (self.username or 'anon') + ('#h' if self.is_hash else '')

    def args(self) -> list[str]:
        out = ['-u', self.username]
        out += ['-H', self.secret] if self.is_hash else ['-p', self.secret]
        if self.domain:
            out += ['-d', self.domain]
        if self.kerberos:
            out += ['-k']
        return out


def nxc(proto: str, target: str, cred: Cred | None = None, module: str | None = None,
        extra: list[str] | None = None, module_opts: dict[str, str] | None = None,
        timeout: int = 90) -> str:
    cmd = ['nxc', proto, target]
    if cred is not None:
        cmd += cred.args()
    if module is not None:
        cmd += ['-M', module]
        for key, value in (module_opts or {}).items():
            cmd += ['-o', f'{key}={value}']
    cmd += extra or []
    return run(*cmd, timeout=timeout)


# ---- parsing ----------------------------------------------------------

def host_rest(line: str) -> tuple[str, str] | None:
    """Return (hostname, rest-of-line) for an nxc status line, else None."""
    m = HOST_LINE.match(line.strip())
    if not m:
        return None
    return m.group(4), m.group(5).strip()


def parse_banner(output: str) -> dict | None:
    """Parse the first SMB banner line into host facts."""
    for line in output.splitlines():
        m = HOST_LINE.match(line.strip())
        if not m or m.group(1) != 'SMB':
            continue

        ip, host, rest = m.group(2), m.group(4), m.group(5)
        name = _BANNER_NAME.search(rest)
        domain = _BANNER_DOMAIN.search(rest)
        signing = _BANNER_SIGNING.search(rest)
        smbv1 = _BANNER_SMBV1.search(rest)

        os = rest
        if rest.startswith('[*]'):
            os = rest[3:].strip()
        cut = os.find('(name:')
        if cut != -1:
            os = os[:cut].strip()

        return {
            'ip': ip,
            'hostname': (name.group(1) if name else host),
            'domain': (domain.group(1) if domain else ''),
            'signing': (signing.group(1) == 'True') if signing else True,
            'smbv1': (smbv1.group(1) == 'True') if smbv1 else False,
            'os': os or None,
        }
    return None


def login_ok(output: str) -> bool:
    """True if nxc reported a successful bind (not just a reachable host)."""
    for line in output.splitlines():
        hr = host_rest(line)
        if hr and hr[1].startswith('[+]') and 'KRB_AP_ERR' not in hr[1]:
            return True
    return False


def pwned(output: str) -> bool:
    return 'Pwn3d!' in output


def parse_rid_brute(output: str) -> list[str]:
    users: list[str] = []
    for m in _RID_LINE.finditer(output):
        if m.group(4) == 'User':
            users.append(m.group(3))
    return users


def parse_users(output: str) -> list[tuple[str, int | None, str | None]]:
    """Parse `--users` output into (username, bad_pwd_count, description)."""
    results: list[tuple[str, int | None, str | None]] = []
    for line in output.splitlines():
        hr = host_rest(line)
        if hr is None:
            continue
        rest = hr[1]
        if not rest or rest.startswith(('[', '-Username-')):
            continue

        tokens = rest.split()
        username = tokens[0]
        if username.lower() in ('-username-', 'username'):
            continue

        bad_pwd: int | None = None
        desc: str | None = None
        # badPwdCount is the first standalone integer after the username
        for i, tok in enumerate(tokens[1:], start=1):
            if tok.isdigit():
                bad_pwd = int(tok)
                tail = ' '.join(tokens[i + 1:]).strip()
                desc = tail or None
                break
        results.append((username, bad_pwd, desc))
    return results


def parse_shares(output: str) -> list[tuple[str, str, str]]:
    """Parse `--shares` output into (name, permissions, remark)."""
    results: list[tuple[str, str, str]] = []
    for line in output.splitlines():
        hr = host_rest(line)
        if hr is None:
            continue
        rest = hr[1]
        if not rest or rest.startswith(('[', 'Share ', '-----')):
            continue
        tokens = rest.split()
        if not tokens:
            continue
        name = tokens[0]
        perms = ''
        remark = ''
        if len(tokens) > 1 and re.fullmatch(r'(READ|WRITE|,)+', tokens[1]):
            perms = tokens[1]
            remark = ' '.join(tokens[2:])
        else:
            remark = ' '.join(tokens[1:])
        results.append((name, perms, remark))
    return results


def tcp_open(ip: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False
