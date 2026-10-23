"""Validate a candidate username list against the KDC (unauthenticated).

Three interchangeable engines, tried in order of preference:
  1. the `kerbrute` binary, if present (purpose-built, fastest);
  2. NetExec -- `nxc smb <dc> -u <list> -p '' -k` -- the native interface the
     rest of autowin already drives; valid accounts answer the empty-password
     AS-REQ with PREAUTH_REQUIRED (or an AS-REP-roast success), non-existent
     ones with PRINCIPAL_UNKNOWN;
  3. nmap's `krb5-enum-users`.

Only usernames the KDC confirms exist are folded into the DB -- with NO
password -- so they then feed roasting, show up in the stored user list and in
`cred list` (as known-but-credless), and are available to spray. Both the
automated discovery (`userenum`) and the manual `spray` subcommand
(`validate_userlist`) go through here.
"""
import os
import re
import tempfile

from .schema import DB, User
from .nxcwrap import host_rest
from .shell import run, have, run_stream
from .console import info, good, warn, Progress

_KERBRUTE_VALID = re.compile(r'VALID USERNAME:\s*([^@\s]+)@', re.I)

# a NetExec per-user auth line: `[+]`/`[-] DOMAIN\user: <outcome>` -- capture user
_NXC_PRINC = re.compile(r'\[[+\-]\]\s+\S+?\\([^\s:]+)')
# a PRINCIPAL_UNKNOWN reply is the KDC saying the account does NOT exist
_NXC_UNKNOWN = re.compile(r'PRINCIPAL_UNKNOWN', re.I)
# any of these replies (or a `[+]` success) prove the account DOES exist
_NXC_EXISTS = re.compile(
    r'PREAUTH_REQUIRED|asreproast|CLIENT_REVOKED|PREAUTH_FAILED|'
    r'ACCOUNT_DISABLED|ACCOUNT_EXPIRED|ACCOUNT_RESTRICTION|'
    r'PASSWORD_EXPIRED|PASSWORD_MUST_CHANGE|LOGON_HOURS|'
    r'LOGON_TYPE_NOT_GRANTED|INVALID_WORKSTATION', re.I)


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


# ---- engines ----------------------------------------------------------

def _via_kerbrute(domain: str, dc_ip: str, userfile: str) -> list[str]:
    out = run('kerbrute', 'userenum', '-d', domain, '--dc', dc_ip, userfile, timeout=600)
    return _KERBRUTE_VALID.findall(out)


def _candidate_count(userfile: str) -> int:
    try:
        with open(userfile, encoding='utf-8', errors='ignore') as f:
            return sum(1 for line in f if line.strip())
    except OSError:
        return 0


def _classify_nxc_line(line: str) -> tuple[str | None, str | None]:
    """Classify one nxc output line -> ('valid'|'invalid'|'other', user) for a
    per-candidate auth line, or (None, None) for anything else (banners, etc)."""
    hr = host_rest(line)
    rest = hr[1] if hr else line.strip()
    m = _NXC_PRINC.search(rest)
    if not m:
        return None, None
    user = m.group(1)
    if _NXC_UNKNOWN.search(rest):
        return 'invalid', user     # KDC says this principal does not exist
    if rest.lstrip().startswith('[+]') or _NXC_EXISTS.search(rest):
        return 'valid', user
    return 'other', user           # reached the KDC but couldn't classify


def _via_nxc(domain: str, dc_ip: str, userfile: str) -> list[str]:
    # empty-password Kerberos pre-auth against the DC; one line per candidate.
    cmd = ['nxc', 'smb', dc_ip, '-u', userfile, '-p', '', '-k',
           '-d', domain, '--continue-on-success']
    valid: list[str] = []
    seen: set[str] = set()
    with Progress(f'kerbrute: {domain}', total=_candidate_count(userfile)) as bar:
        for line in run_stream(*cmd, timeout=600):
            kind, user = _classify_nxc_line(line)
            if kind is None:
                continue
            bar.update()               # one candidate resolved
            if kind == 'valid' and user not in seen:
                seen.add(user)
                valid.append(user)
    return valid


def _via_nmap(domain: str, dc_ip: str, userfile: str) -> list[str]:
    realm = domain.upper()
    out = run('nmap', '-p', '88', '--script', 'krb5-enum-users',
              '--script-args', f'krb5-enum-users.realm={realm},userdb={userfile}',
              dc_ip, timeout=600)
    # valid principals print as `  user@REALM`
    return re.findall(rf'([A-Za-z0-9._$-]+)@{re.escape(realm)}', out)


def _parse_nxc(output: str) -> list[str]:
    """Pull confirmed-valid usernames out of `nxc smb -u file -p '' -k` output."""
    valid: list[str] = []
    seen: set[str] = set()
    for line in output.splitlines():
        kind, user = _classify_nxc_line(line)
        if kind == 'valid' and user not in seen:
            seen.add(user)
            valid.append(user)
    return valid


_ENGINES: dict[str, tuple[str, object]] = {
    'kerbrute': ('kerbrute', _via_kerbrute),
    'nxc': ('netexec (kerberos)', _via_nxc),
    'nmap': ('nmap krb5-enum-users', _via_nmap),
}
_PREFERENCE = ('kerbrute', 'nxc', 'nmap')
# the binary each engine needs on PATH
_ENGINE_TOOL = {'kerbrute': 'kerbrute', 'nxc': 'nxc', 'nmap': 'nmap'}


def _select_engine(prefer: str | None = None):
    """Return (name, label, fn) for the first usable engine, or None."""
    order = ([prefer] if prefer else []) + [e for e in _PREFERENCE if e != prefer]
    for name in order:
        spec = _ENGINES.get(name)
        if spec and have(_ENGINE_TOOL[name]):
            return name, spec[0], spec[1]
    return None


# ---- public entry points ----------------------------------------------

def validate_userlist(dc_ip: str, domain: str, users: list[str],
                      prefer: str = 'nxc') -> list[str]:
    """Validate an in-memory username list against one DC. Store-agnostic.

    Returns the confirmed-valid usernames. Used by the `spray` subcommand,
    which defaults to the NetExec engine. Callers persist the result.
    """
    selected = _select_engine(prefer)
    if selected is None:
        warn('kerbrute: no user-validation engine available (need kerbrute, nxc, or nmap)')
        return []
    _name, label, fn = selected

    fd, raw = tempfile.mkstemp(prefix='autowin-cand-raw-')
    with os.fdopen(fd, 'w') as f:
        for u in users:
            u = u.strip()
            if u:
                f.write(u + '\n')
    userfile = _normalize_userlist(raw)
    try:
        info(f'kerbrute: validating {len(users)} candidate user(s) against {domain} via {label}')
        valid = sorted({u for u in fn(domain, dc_ip, userfile) if u})
        for name in valid:
            good(f'kerbrute: valid user {domain}\\{name}')
        return valid
    finally:
        for p in (raw, userfile):
            try:
                os.unlink(p)
            except OSError:
                pass


def userenum(db: DB, userlist: str) -> None:
    """Discovery path: validate a candidate file against every known DC and
    fold the confirmed users into the DB (no password)."""
    if not os.path.isfile(userlist):
        warn(f'kerbrute: candidate user list not found: {userlist}')
        return
    selected = _select_engine()
    if selected is None:
        warn('kerbrute: neither kerbrute, nxc, nor nmap found; skipping user validation')
        return
    _name, label, fn = selected

    userfile = _normalize_userlist(userlist)
    try:
        for domain in db._domains.values():
            if domain.dc is None:
                continue
            key = f'kerbrute:{domain.name}:{os.path.getsize(userfile)}'
            if db.store and db.store.is_done(key):
                continue

            info(f'kerbrute: validating candidate users against {domain} via {label}')
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
