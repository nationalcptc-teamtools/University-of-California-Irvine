"""Network recon: host discovery and user/share enumeration."""
import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from schema import DB, Box, Share, User
from nxcwrap import nxc, Cred, parse_banner, parse_users, parse_shares, parse_rid_brute, login_ok, pwned, tcp_open
from console import info, err

_RANGE = re.compile(r'^(\d+\.\d+\.\d+)\.(\d+)-(\d+)$')


def expand_targets(spec: str) -> list[str]:
    """Expand an IP / CIDR / a.b.c.d-e / comma-or-space list into addresses."""
    targets: list[str] = []
    for token in re.split(r'[,\s]+', spec.strip()):
        if not token:
            continue
        m = _RANGE.match(token)
        try:
            if m:
                base, lo, hi = m.group(1), int(m.group(2)), int(m.group(3))
                targets += [f'{base}.{i}' for i in range(lo, hi + 1)]
            elif '/' in token:
                targets += [str(ip) for ip in ipaddress.ip_network(token, strict=False).hosts()]
            else:
                targets.append(token)
        except ValueError:
            err(f'recon: cannot parse target {token}')
    return targets


def recon(db: DB, spec: str, threads: int = 64, exclude: str = '', rescan: bool = False) -> None:
    done_key = f'recon:{spec}:{exclude}'
    if db.store and db.store.is_done(done_key) and not rescan:
        info(f'recon: already scanned {spec} (resume); {len(db._hosts)} known host(s) — use --rescan to redo')
        return

    def probe(ip: str) -> None:
        # fast TCP pre-filter: skip spawning nxc for hosts without SMB open
        if not tcp_open(ip, 445, timeout=1.0):
            return
        output = nxc('smb', ip, Cred.anonymous(), timeout=20)
        facts = parse_banner(output)
        if facts is None or not facts['domain']:
            return

        box = Box(
            ip=facts['ip'],
            hostname=facts['hostname'],
            domain=db.domain(facts['domain']),
            dc=tcp_open(ip, 389),
            signing=facts['signing'],
            smbv1=facts['smbv1'],
            smb_null_auth=login_ok(output),
            os=facts['os'],
        )
        db.add_box(box)

    targets = expand_targets(spec)
    if exclude:
        excluded = set(expand_targets(exclude))
        targets = [t for t in targets if t not in excluded]
        if excluded:
            info(f'recon: excluding {len(excluded)} host(s)')
    info(f'recon: scanning {len(targets)} host(s)...')
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(probe, ip) for ip in targets]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                err(f'recon: error while scanning: {e}')
    if db.store:
        db.store.mark_done(done_key)


def _skip(db: DB, key: str) -> bool:
    return bool(db.store and db.store.is_done(key))


def _mark(db: DB, key: str) -> None:
    if db.store:
        db.store.mark_done(key)


def enumerate_users(db: DB, cred: Cred) -> None:
    """SMB --users + --rid-brute against every known box, into the DB."""
    for box in list(db._hosts.values()):
        if cred.domain and db.domain(cred.domain) is not box.domain:
            continue
        key = f'users:{box.hostname}:{cred.key()}'
        if _skip(db, key):
            continue

        output = nxc('smb', box.ip, cred, extra=['--users'])
        for name, bad_pwd, desc in parse_users(output):
            db.add_user(User(name=name, owner=box, bad_pwd_count=bad_pwd, description=desc))

        output = nxc('smb', box.ip, cred, extra=['--rid-brute'])
        for name in parse_rid_brute(output):
            db.add_user(User(name=name, owner=box))
        _mark(db, key)


def ldap_enumerate_users(db: DB, cred: Cred) -> None:
    """Richer user enumeration via LDAP against the domain's DC."""
    for domain in db._domains.values():
        if domain.dc is None:
            continue
        if cred.domain and db.domain(cred.domain) is not domain:
            continue
        key = f'ldapusers:{domain.name}:{cred.key()}'
        if _skip(db, key):
            continue

        output = nxc('ldap', domain.dc.ip, cred, extra=['--users'])
        for name, bad_pwd, desc in parse_users(output):
            db.add_user(User(name=name, owner=domain.dc, bad_pwd_count=bad_pwd, description=desc))
        _mark(db, key)


def enumerate_shares(db: DB, cred: Cred) -> None:
    for box in list(db._hosts.values()):
        if cred.domain and db.domain(cred.domain) is not box.domain:
            continue
        key = f'shares:{box.hostname}:{cred.key()}'
        if _skip(db, key):
            continue

        output = nxc('smb', box.ip, cred, extra=['--shares'])
        for name, perms, remark in parse_shares(output):
            db.add_share(Share(
                name=name,
                owner=box,
                description=remark,
                readable='READ' in perms,
                writable='WRITE' in perms,
            ))
        _mark(db, key)
