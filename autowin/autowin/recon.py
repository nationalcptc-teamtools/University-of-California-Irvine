"""Network recon: host discovery and user/share enumeration."""
import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from .schema import DB, Box, Share, User, Vuln
from .nxcwrap import nxc, Cred, parse_banner, parse_users, parse_shares, parse_rid_brute, login_ok, pwned, tcp_open, host_rest
from .console import info, err, good, Progress

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
        with Progress('recon: scanning hosts', total=len(futures)) as bar:
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    err(f'recon: error while scanning: {e}')
                bar.update()
    if db.store:
        db.store.mark_done(done_key)


def _skip(db: DB, key: str) -> bool:
    return bool(db.store and db.store.is_done(key))


def _mark(db: DB, key: str) -> None:
    if db.store:
        db.store.mark_done(key)


def enumerate_users(db: DB, cred: Cred) -> None:
    """SMB --users + --rid-brute against every known box, into the DB."""
    boxes = list(db._hosts.values())
    with Progress(f'enum users ({cred.label()})', total=len(boxes)) as bar:
        for box in boxes:
            if cred.domain and db.domain(cred.domain) is not box.domain:
                bar.update()
                continue
            key = f'users:{box.hostname}:{cred.key()}'
            if _skip(db, key):
                bar.update()
                continue

            output = nxc('smb', box.ip, cred, extra=['--users'], show=True,
                         save=(db.store, cred.context(), f'users_{box.hostname}'))
            for name, bad_pwd, desc in parse_users(output):
                db.add_user(User(name=name, owner=box, bad_pwd_count=bad_pwd, description=desc))

            output = nxc('smb', box.ip, cred, extra=['--rid-brute'], show=True,
                         save=(db.store, cred.context(), f'rid-brute_{box.hostname}'))
            for name in parse_rid_brute(output):
                db.add_user(User(name=name, owner=box))
            _mark(db, key)
            bar.update()


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

        output = nxc('ldap', domain.dc.ip, cred, extra=['--users'], show=True,
                     save=(db.store, cred.context(), f'ldap-users_{domain.name}'))
        for name, bad_pwd, desc in parse_users(output):
            db.add_user(User(name=name, owner=domain.dc, bad_pwd_count=bad_pwd, description=desc))
        _mark(db, key)


def enumerate_shares(db: DB, cred: Cred) -> None:
    boxes = list(db._hosts.values())
    with Progress(f'enum shares ({cred.label()})', total=len(boxes)) as bar:
        for box in boxes:
            if cred.domain and db.domain(cred.domain) is not box.domain:
                bar.update()
                continue
            key = f'shares:{box.hostname}:{cred.key()}'
            if _skip(db, key):
                bar.update()
                continue

            output = nxc('smb', box.ip, cred, extra=['--shares'], show=True,
                         save=(db.store, cred.context(), f'shares_{box.hostname}'))
            for name, perms, remark in parse_shares(output):
                db.add_share(Share(
                    name=name,
                    owner=box,
                    description=remark,
                    readable='READ' in perms,
                    writable='WRITE' in perms,
                ))
            _mark(db, key)
            bar.update()


# ---- password policy ---------------------------------------------------

def _parse_pass_pol(output: str) -> dict:
    """Parse `nxc smb --pass-pol` output into an ordered key->value dict."""
    policy: dict[str, str] = {}
    for line in output.splitlines():
        hr = host_rest(line)
        if hr is None:
            continue
        rest = hr[1].strip()
        if not rest or rest.startswith(('[', '-')):
            continue                      # skip [+]/[*] status and separators
        key, sep, value = rest.partition(':')
        if not sep:
            continue
        key, value = key.strip(), value.strip()
        if key and value and key not in policy:
            policy[key] = value
    return policy


def _find(policy: dict, needle: str):
    needle = needle.lower()
    for key, value in policy.items():
        if needle in key.lower():
            return value
    return None


def _policy_findings(policy: dict) -> list[tuple[str, str]]:
    """Flag the CPTC-reportable weaknesses in a parsed password policy."""
    findings: list[tuple[str, str]] = []

    min_len = _find(policy, 'minimum password length')
    try:
        if min_len is not None and int(min_len) < 8:
            findings.append(('Weak minimum password length',
                             f'minimum password length is {min_len} (< 8)'))
    except ValueError:
        pass

    lockout = _find(policy, 'lockout threshold')
    if lockout is not None and lockout.strip().lower() in ('none', '0', 'disabled'):
        findings.append(('No account lockout policy',
                         f'account lockout threshold is {lockout} (no lockout)'))

    # the per-flag "Domain Password Complex: 0" (not the "Complexity Flags" blob)
    for pkey, pval in policy.items():
        if 'complex' in pkey.lower() and pval.strip() in ('0', 'False', 'false'):
            findings.append(('Password complexity disabled',
                             'domain does not enforce password complexity'))
            break

    return findings


def enumerate_password_policy(db: DB, cred: Cred) -> None:
    """Dump the domain password policy (SAMR) and fold it into the DB.

    Tries each context (anonymous/guest/credential) once per domain, but stops
    as soon as a policy is recovered. Weak settings are flagged as vulns so
    they surface in the report (useful for CPTC write-ups).
    """
    for domain in db._domains.values():
        if domain.dc is None or domain.password_policy:
            continue
        if cred.domain and db.domain(cred.domain) is not domain:
            continue
        key = f'passpol:{domain.name}:{cred.key()}'
        if _skip(db, key):
            continue

        policy = _parse_pass_pol(nxc('smb', domain.dc.ip, cred, extra=['--pass-pol'], show=True,
                                     save=(db.store, cred.context(), f'pass-pol_{domain.name}')))
        if policy:
            domain.password_policy = policy
            good(f'password policy recovered for {domain} ({len(policy)} setting(s))')
            if db.store:
                for pkey, pval in policy.items():
                    db.store.add_policy(domain.name, pkey, pval)
            for title, detail in _policy_findings(policy):
                db.add_vuln(Vuln(title=title, owner=domain.dc,
                                 source='pass-pol', detail=detail))
        _mark(db, key)
