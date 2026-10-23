"""Validate a candidate username list against the KDC (unauthenticated).

Prefers the `kerbrute` binary if present, otherwise falls back to nmap's
`krb5-enum-users`. Only usernames the KDC confirms exist are folded into the DB,
so they then feed roasting, the stored user list, and (manual) spraying.
"""
import os
import re
import tempfile

from schema import DB, User
from nxcwrap import nxc  # noqa: F401  (kept for symmetry; not used directly)
from shell import run, have
from console import info, good, warn

_KERBRUTE_VALID = re.compile(r'VALID USERNAME:\s*([^@\s]+)@', re.I)


def _normalize_userlist(path: str) -> str:
    """Rewrite a candidate list to bare, de-duplicated usernames.

    Accepts `user`, `DOMAIN\\user`, or `user@domain` per line.
    """
    seen: set[str] = set()
    fd, out = tempfile.mkstemp(prefix='autowin-cand-')
    with os.fdopen(fd, 'w') as f:
        with open(path, encoding='utf-8', errors='ignore') as src:
            for line in src:
                name = line.strip()
                if not name or name.startswith('#'):
                    continue
                if '\\' in name:
                    name = name.split('\\', 1)[1]
                if '@' in name:
                    name = name.split('@', 1)[0]
                if name and name not in seen:
                    seen.add(name)
                    f.write(name + '\n')
    return out


def _via_kerbrute(domain: str, dc_ip: str, userfile: str) -> list[str]:
    out = run('kerbrute', 'userenum', '-d', domain, '--dc', dc_ip, userfile, timeout=600)
    return _KERBRUTE_VALID.findall(out)


def _via_nmap(domain: str, dc_ip: str, userfile: str) -> list[str]:
    realm = domain.upper()
    out = run('nmap', '-p', '88', '--script', 'krb5-enum-users',
              '--script-args', f'krb5-enum-users.realm={realm},userdb={userfile}',
              dc_ip, timeout=600)
    # valid principals print as `  user@REALM`
    return re.findall(rf'([A-Za-z0-9._$-]+)@{re.escape(realm)}', out)


def userenum(db: DB, userlist: str) -> None:
    if not os.path.isfile(userlist):
        warn(f'kerbrute: candidate user list not found: {userlist}')
        return
    if have('kerbrute'):
        engine, fn = 'kerbrute', _via_kerbrute
    elif have('nmap'):
        engine, fn = 'nmap krb5-enum-users', _via_nmap
    else:
        warn('kerbrute: neither kerbrute nor nmap found; skipping user validation')
        return

    userfile = _normalize_userlist(userlist)
    try:
        for domain in db._domains.values():
            if domain.dc is None:
                continue
            key = f'kerbrute:{domain.name}:{os.path.getsize(userfile)}'
            if db.store and db.store.is_done(key):
                continue

            info(f'kerbrute: validating candidate users against {domain} via {engine}')
            valid = {u for u in fn(domain.name, domain.dc.ip, userfile) if u}
            for name in sorted(valid):
                db.add_user(User(name=name, owner=domain.dc))
            good(f'kerbrute: {len(valid)} valid user(s) in {domain}')
            if db.store:
                db.store.mark_done(key)
    finally:
        try:
            os.unlink(userfile)
        except OSError:
            pass
