"""Operator-driven SMB interaction: list shares, drop into a shell, or
recursively loot a share to local disk.

Everything here is explicit (never part of auto-discovery) and drives external
binaries so it works across tool versions and supports password, NTLM-hash and
Kerberos auth:
  * shares   -> NetExec   (`nxc smb ... --shares`)
  * shell    -> impacket  (`impacket-smbclient`, interactive)
  * download -> Samba      (`smbclient ... -c 'recurse ON; prompt OFF; mget *'`)
"""
import os

from .nxcwrap import nxc, Cred, parse_shares
from .shell import stream, have
from .console import info, good, err, warn


def list_shares(target: str, cred: Cred) -> list[tuple[str, str, str]]:
    """Enumerate shares on `target` and print them. Returns the parsed rows."""
    rows = parse_shares(nxc('smb', target, cred, extra=['--shares']))
    if not rows:
        warn(f'smb: no shares listed on {target} (auth failed or none readable)')
        return rows
    good(f'smb: {len(rows)} share(s) on {target}')
    for name, perms, remark in rows:
        tag = f' [{perms}]' if perms else ''
        suffix = f'  {remark}' if remark else ''
        print(f'  {name}{tag}{suffix}')
    return rows


# ---- auth argument builders -------------------------------------------

def _impacket_args(target: str, cred: Cred, dc_ip: str | None) -> list[str]:
    authority = f'{cred.domain}/{cred.username}' if cred.domain else cred.username
    args: list[str] = []
    if cred.is_hash:
        spec = f'{authority}@{target}'
        # accept either a bare NT hash or a full LM:NT pair
        hashes = cred.secret if ':' in cred.secret else f':{cred.secret}'
        args += ['-hashes', hashes]
    elif cred.kerberos:
        spec = f'{authority}@{target}'
        args += ['-k', '-no-pass']
    elif cred.secret:
        spec = f'{authority}:{cred.secret}@{target}'
    else:
        spec = f'{authority}@{target}'
        args += ['-no-pass']
    if dc_ip:
        args += ['-dc-ip', dc_ip]
    return args + [spec]


def _smbclient_auth(cred: Cred) -> list[str]:
    userarg = f'{cred.domain}\\{cred.username}' if cred.domain else cred.username
    if cred.kerberos:
        return ['-k'] + (['-W', cred.domain] if cred.domain else [])
    if cred.is_hash:
        nt = cred.secret.split(':')[-1]      # Samba wants just the NT hash
        return ['-U', f'{userarg}%{nt}', '--pw-nt-hash']
    if cred.username or cred.secret:
        return ['-U', f'{userarg}%{cred.secret}']
    return ['-N']   # anonymous / null session


# ---- actions ----------------------------------------------------------

def shell(target: str, cred: Cred, dc_ip: str | None = None) -> None:
    """Drop into an interactive SMB shell (impacket-smbclient)."""
    if not have('impacket-smbclient'):
        err('smb: impacket-smbclient not found on PATH (install impacket)')
        return
    info(f'smb: opening shell on {target} as {cred.label()} (Ctrl-D / `exit` to quit)')
    stream('impacket-smbclient', *_impacket_args(target, cred, dc_ip))


def download(target: str, cred: Cred, share: str, outdir: str,
             dc_ip: str | None = None) -> None:
    """Recursively download an entire share into `outdir`."""
    if not have('smbclient'):
        err('smb: smbclient (Samba) not found on PATH')
        return
    dest = os.path.abspath(outdir)
    os.makedirs(dest, exist_ok=True)
    unc = f'//{target}/{share}'
    # recurse+mget pulls the whole tree, recreating directories under lcd
    commands = f'recurse ON; prompt OFF; lcd "{dest}"; mget *'
    args = _smbclient_auth(cred) + [unc, '-c', commands]
    if dc_ip:
        args += ['-I', dc_ip]   # connect to this IP even if target is a hostname
    info(f'smb: downloading {unc} -> {dest}')
    rc = stream('smbclient', *args)
    (good if rc == 0 else warn)(f'smb: download of {share} finished (smbclient exit {rc})')
