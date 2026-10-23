"""Run NetExec's BloodHound ingestor once per domain on the first valid cred."""
import re
import shutil
from pathlib import Path

from .schema import DB
from .nxcwrap import nxc, Cred
from .console import info, good, err

_ZIP = re.compile(r"(/[^\s'\"]+\.zip|[A-Za-z0-9_.-]+\.zip)")


def run_bloodhound(db: DB, collection: str = 'all', dns_tcp: bool = False) -> None:
    """For each domain, if we have a credential and haven't collected yet,
    run `nxc ldap --bloodhound` a single time and stash the resulting zip."""
    for domain in db._domains.values():
        if domain.dc is None:
            continue
        if db.store and db.store.bloodhound_done(domain.name):
            continue

        cred = None
        for user in db._users:
            if user.domain is domain and user.password is not None:
                cred = Cred(user.name, user.password, domain.name)
                break
        if cred is None:
            continue   # no usable credential for this domain yet

        info(f'bloodhound: collecting {domain} as {cred.username} (one-shot)')
        extra = ['--bloodhound', '-c', collection, '--dns-server', domain.dc.ip]
        if dns_tcp:
            extra.append('--dns-tcp')
        output = nxc('ldap', domain.dc.ip, cred, extra=extra, timeout=900)

        stored = _stash_zip(db, output, domain.name)
        if stored:
            good(f'bloodhound: saved {stored}')
        else:
            good(f'bloodhound: completed for {domain} (see nxc output / ~/.nxc for the zip)')

        if db.store:
            db.store.mark_bloodhound(domain.name, cred.username)


def _stash_zip(db: DB, output: str, domain: str) -> str | None:
    if not db.store:
        return None
    for token in _ZIP.findall(output):
        src = Path(token)
        if src.is_file():
            dest = db.store.bloodhound_dir / f'{domain}_{src.name}'
            try:
                shutil.copy2(src, dest)
                return str(dest)
            except OSError:
                return None
    return None
