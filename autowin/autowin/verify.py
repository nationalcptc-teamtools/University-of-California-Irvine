"""Verify credentials and note whether an account can get a shell.

Called for every credential autowin learns -- automatically during discovery
(`verify_access`, which supersedes the old admin-only check) and immediately on
a manual `config cred add` (`check_cred`).

A credential is *valid* if it authenticates over SMB. It can get a *shell* if:
  * SMB reports `Pwn3d!` (local admin -> psexec/smbexec/wmiexec), or
  * WinRM login succeeds (evil-winrm).
Results are recorded on the user (admin_on / winrm_on / verified) and persisted
to the store's cred_status table so they show up in `config cred list`.
"""
from .nxcwrap import nxc, Cred, login_ok, pwned, tcp_open
from .schema import DB
from .console import good, info, Progress


def check_cred(domain: str, user: str, secret: str, is_hash: bool,
               target: str, kerberos: bool = False) -> tuple[bool, set[str]]:
    """Validate one credential against one target. Returns (valid, shell_kinds)."""
    cred = Cred(user, secret, domain, is_hash=is_hash, kerberos=kerberos)
    shells: set[str] = set()
    smb = nxc('smb', target, cred, timeout=30)
    valid = login_ok(smb)
    if pwned(smb):
        shells.add('smb')
    if tcp_open(target, 5985):
        win = nxc('winrm', target, cred, timeout=30)
        if login_ok(win):          # WinRM is a shell protocol: login == shell
            shells.add('winrm')
            valid = True
    return valid, shells


def check_cred_hosts(domain: str, user: str, secret: str, is_hash: bool,
                     hosts: list[tuple[str, str]],
                     kerberos: bool = False) -> tuple[bool, dict[str, set[str]]]:
    """Check a credential against several hosts (list of (label, ip)). Returns
    (any_valid, {label: shell_kinds}) -- i.e. whether and where it gets a shell."""
    any_valid = False
    shells_by_host: dict[str, set[str]] = {}
    for label, ip in hosts:
        valid, shells = check_cred(domain, user, secret, is_hash, ip, kerberos=kerberos)
        any_valid = any_valid or valid or bool(shells)
        if shells:
            shells_by_host[label] = shells
    return any_valid, shells_by_host


def verify_access(db: DB, users=None) -> None:
    """For every credentialed user, probe each host over SMB (validity + admin
    shell) and WinRM (shell), recording the results and persisting cred_status.

    Pass `users` to verify only a specific subset (e.g. the sweep-only path
    verifies just the selected credential, not the whole store)."""
    users = users if users is not None else db.credentialed_users()
    total = sum(len(db.boxes_in(u.domain)) for u in users)
    with Progress('verifying creds', total=total) as bar:
        for user in users:
            try:
                cred = Cred.from_user(user)
            except ValueError:
                bar.update(len(db.boxes_in(user.domain)))
                continue

            checked = False
            valid = False
            for box in db.boxes_in(user.domain):
                skey = f'verify-smb:{box.hostname}:{cred.key()}'
                if not (db.store and db.store.is_done(skey)):
                    checked = True
                    out = nxc('smb', box.ip, cred, timeout=30)
                    if login_ok(out):
                        valid = True
                    if pwned(out) and box.hostname not in user.admin_on:
                        user.admin_on.add(box.hostname)
                        good(f'{user.domain}\\{user.name} is admin on {box.hostname} (SMB shell)')
                    if db.store:
                        db.store.mark_done(skey)

                wkey = f'verify-winrm:{box.hostname}:{cred.key()}'
                if tcp_open(box.ip, 5985) and not (db.store and db.store.is_done(wkey)):
                    checked = True
                    win = nxc('winrm', box.ip, cred, timeout=30)
                    if login_ok(win):
                        valid = True
                        if box.hostname not in user.winrm_on:
                            user.winrm_on.add(box.hostname)
                            good(f'{user.domain}\\{user.name} can WinRM to {box.hostname} (shell)')
                    if db.store:
                        db.store.mark_done(wkey)
                bar.update()

            if valid:
                user.verified = True
            _persist(db, user, valid, checked)


def _persist(db: DB, user, valid: bool, checked: bool) -> None:
    """Write (merged) cred_status; on a fully-resumed user, leave it untouched."""
    if not db.store or not checked:
        return
    shells = set(user.shells())
    prior = db.store.get_cred_status(user.domain.name, user.name)
    if prior and prior['shell']:
        shells |= {s for s in prior['shell'].split(',') if s}
    ever_valid = valid or user.verified or bool(prior and prior['valid'])
    db.store.set_cred_status(user.domain.name, user.name,
                             ever_valid or bool(shells), ','.join(sorted(shells)))
