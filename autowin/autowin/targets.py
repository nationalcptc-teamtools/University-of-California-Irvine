"""Target bookkeeping helpers: keep /etc/hosts in step with discovered hosts.

Entries are written in NetExec's `--generate-hosts-file` format
(`ip  host.domain [domain if DC]  host`) but built from the stored host facts
we already collected during discovery -- so syncing needs no extra network
round-trip and still works for offline or manually-added hosts. New entries
are appended, de-duplicated against what is already in the file.
"""
import os

from .console import info, good, warn

HOSTS_PATH = '/etc/hosts'


def _db_lines(hosts: list[dict]) -> list[str]:
    """Build hosts-file lines (NetExec format) from stored host records."""
    lines: list[str] = []
    for h in hosts:
        ip, host, dom = h.get('ip'), h.get('hostname'), h.get('domain') or ''
        if not ip or not host:
            continue
        fqdn = f'{host}.{dom}' if dom else host
        dc_part = f' {dom}' if h.get('dc') and dom else ''
        lines.append(f'{ip}     {fqdn}{dc_part} {host}')
    return lines


def _existing_names(path: str) -> set[str]:
    names: set[str] = set()
    try:
        with open(path, encoding='utf-8', errors='ignore') as f:
            for line in f:
                if line.lstrip().startswith('#'):
                    continue
                parts = line.split()
                for tok in parts[1:]:          # every name mapped on the line
                    names.add(tok.lower())
    except OSError:
        pass
    return names


def sync_etc_hosts(store, path: str = HOSTS_PATH) -> None:
    """Append new discovered hosts to /etc/hosts (deduped by hostname)."""
    hosts = store.list_hosts()
    if not hosts:
        return
    lines = _db_lines(hosts)
    if not lines:
        return

    existing = _existing_names(path)
    new = [ln for ln in lines if ln.split()[1].lower() not in existing]
    if not new:
        info(f'hosts: {path} already up to date')
        return

    block = '\n'.join(new) + '\n'
    try:
        with open(path, 'a', encoding='utf-8') as f:
            f.write(block)
        good(f'hosts: appended {len(new)} entr{"y" if len(new) == 1 else "ies"} to {path}')
    except PermissionError:
        out = store.dir / 'hosts.append'
        with open(out, 'a', encoding='utf-8') as f:
            f.write(block)
        warn(f'hosts: cannot write {path} without root; wrote entries to {out} '
             f'(append them with:  sudo tee -a {path} < {out})')
