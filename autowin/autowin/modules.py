"""The NetExec vulnerability / CVE / loot module sweep.

A curated registry of the "main" nxc modules (ported from autoWin's module
spam, plus a few high-value additions). Every spec is filtered against the
modules actually installed, so unknown names are skipped harmlessly.
"""
import re
from dataclasses import dataclass
from typing import Literal
from concurrent.futures import ThreadPoolExecutor, as_completed

from .schema import DB, Box, User
from .nxcwrap import nxc, Cred, host_rest
from .shell import run
from .console import info, err, warn, plain, Progress

Kind = Literal['vuln', 'loot', 'info']


@dataclass(frozen=True)
class ModuleSpec:
    proto: str
    name: str
    title: str
    kind: Kind = 'vuln'
    cve: str | None = None


# ---- the registry -----------------------------------------------------

MODULES: list[ModuleSpec] = [
    # --- SMB: remote-code / privesc CVEs ---
    ModuleSpec('smb', 'ms17-010',        'EternalBlue',                 'vuln', 'CVE-2017-0144'),
    ModuleSpec('smb', 'zerologon',       'ZeroLogon',                   'vuln', 'CVE-2020-1472'),
    ModuleSpec('smb', 'nopac',           'noPac',                       'vuln', 'CVE-2021-42278/42287'),
    ModuleSpec('smb', 'printnightmare',  'PrintNightmare',              'vuln', 'CVE-2021-1675/34527'),
    ModuleSpec('smb', 'smbghost',        'SMBGhost',                    'vuln', 'CVE-2020-0796'),
    ModuleSpec('smb', 'coerce_plus',     'Authentication coercion',     'vuln', 'PetitPotam/DFSCoerce'),
    ModuleSpec('ldap', 'badsuccessor',   'BadSuccessor (dMSA)',         'vuln'),
    ModuleSpec('smb', 'backup_operator', 'Backup Operators -> NTDS',    'vuln'),
    ModuleSpec('smb', 'ntlmv1',          'NTLMv1 downgrade allowed',    'vuln'),
    ModuleSpec('smb', 'webdav',          'WebClient/WebDAV running',    'vuln'),

    # --- LDAP: AD misconfig ---
    ModuleSpec('ldap', 'maq',            'MachineAccountQuota',         'info'),
    ModuleSpec('ldap', 'adcs',           'ADCS present',                'info'),
    ModuleSpec('ldap', 'ldap-checker',   'LDAP signing / channel bind', 'vuln'),
    ModuleSpec('ldap', 'laps',           'LAPS readable',               'loot'),
    ModuleSpec('ldap', 'get-desc-users', 'User descriptions',           'loot'),
    ModuleSpec('ldap', 'get-userPassword', 'LDAP userPassword attr',    'loot'),
    ModuleSpec('ldap', 'get-unixUserPassword', 'LDAP unixUserPassword', 'loot'),

    # --- SMB: credential loot (needs admin) ---
    ModuleSpec('smb', 'lsassy',             'LSASS secrets',            'loot'),
    ModuleSpec('smb', 'dpapi_hash',         'DPAPI hashes',             'loot'),
    ModuleSpec('smb', 'gpp_autologin',      'GPP autologin creds',      'loot'),
    ModuleSpec('smb', 'gpp_password',       'GPP cpassword',            'loot'),
    ModuleSpec('smb', 'eventlog_creds',     'Credentials in event log', 'loot'),
    ModuleSpec('smb', 'powershell_history', 'PowerShell history',       'loot'),
    ModuleSpec('smb', 'rdcman',             'RDCMan saved sessions',    'loot'),
    ModuleSpec('smb', 'vnc',                'VNC passwords',            'loot'),
    ModuleSpec('smb', 'keepass_discover',   'KeePass databases',        'loot'),
    ModuleSpec('smb', 'putty',              'PuTTY private keys',       'loot'),
    ModuleSpec('smb', 'mremoteng',          'mRemoteNG creds',          'loot'),
    ModuleSpec('smb', 'winscp',             'WinSCP saved sessions',    'loot'),
    ModuleSpec('smb', 'wifi',               'Wi-Fi passwords',          'loot'),
    ModuleSpec('smb', 'notepad',            'Notepad tabs',             'loot'),
    ModuleSpec('smb', 'veeam',              'Veeam creds',              'loot'),
    ModuleSpec('ldap', 'sccm',              'SCCM infrastructure',      'loot'),

    # --- SMB: informational posture ---
    ModuleSpec('smb', 'bitlocker',       'BitLocker status',            'info'),
    ModuleSpec('smb', 'enum_av',         'Installed AV/EDR',            'info'),
    ModuleSpec('smb', 'uac',             'UAC configuration',           'info'),

    # --- MSSQL ---
    ModuleSpec('mssql', 'enum_impersonate', 'MSSQL impersonation',      'vuln'),
    ModuleSpec('mssql', 'enum_links',       'MSSQL linked servers',     'loot'),
    ModuleSpec('mssql', 'enum_logins',      'MSSQL logins',             'loot'),
]

# the `[+] domain\user:secret` echo nxc prints on a (successful) login; the
# username may be empty for an anonymous/null bind (`[+] domain\:`), hence [^\s]*
_AUTH_ECHO = re.compile(r'^\[[+\-]\]\s+\S+\\[^\s]*:')
# conservative loot harvest: DOMAIN\user:plaintext (plaintext not a bare NTLM hash)
_LOOT_CRED = re.compile(r'([A-Za-z0-9.\-]+)\\([A-Za-z0-9._$\-]+):([^\s:]{2,})')

# nxc prints module output with the MODULE NAME (not the protocol) as the first
# column, e.g. `ENUM_AV  10.0.0.5  445  HOST  Found ...`; match that 5-column
# shape for any leading token so module findings aren't dropped.
_MOD_LINE = re.compile(r'^([A-Za-z0-9_.\-]+)\s+\S+\s+\d+\s+\S+\s+(.*)$')

_available: dict[str, set[str]] = {}


def available(proto: str) -> set[str]:
    if proto not in _available:
        out = run('nxc', proto, '-L', timeout=60)
        names: set[str] = set()
        for line in out.splitlines():
            hr = line.strip().split()
            # lines look like: `[*] module_name   description...`
            if len(hr) >= 2 and hr[0] == '[*]':
                names.add(hr[1])
        if not names:
            # `nxc <proto> -L` returned no modules -- usually an nxc-side error
            # (e.g. the MSSQL workspace DB schema mismatch). Surface it.
            first = next((l.strip() for l in out.splitlines() if l.strip()), '')
            warn(f'sweep: no {proto} modules available (nxc {proto} -L said: {first!r}); '
                 f'skipping all {proto} modules')
        _available[proto] = names
    return _available[proto]


def _report_lines(output: str) -> list[str]:
    """Pull a module's own output lines for manual review: drop the host banner
    and the login echo, keep whatever the module actually printed."""
    lines: list[str] = []
    for line in output.splitlines():
        m = _MOD_LINE.match(line.strip())
        if m is None:
            continue
        rest = m.group(2).strip()
        if not rest or _AUTH_ECHO.match(rest):
            continue
        # skip the connection banner (`[*] Windows ... (name:..)(domain:..)`)
        if rest.startswith('[*]') and ('(name:' in rest or '(domain:' in rest):
            continue
        lines.append(rest)
    return lines


def _harvest_creds(db: DB, box: Box, module: str, output: str) -> None:
    for line in output.splitlines():
        hr = host_rest(line)
        # skip nxc's own login echo (`[+] dom\user:secret`) to avoid scraping
        # the credential we authenticated with, or a failed-login attempt
        rest = hr[1] if hr else line
        if _AUTH_ECHO.match(rest.strip()):
            continue
        for m in _LOOT_CRED.finditer(line):
            _dom, user, secret = m.group(1), m.group(2), m.group(3)
            if re.fullmatch(r'[0-9a-fA-F]{32}', secret):
                continue   # looks like a bare NTLM hash, not a plaintext loot cred
            owner = box.domain.dc or box
            existing = db.find_user(box.domain, user)
            if existing is None:
                existing = User(name=user, owner=owner)
                db.add_user(existing)
            db.set_password(existing, secret, source=f'loot:{module}', host=box.hostname)


def _contexts(db: DB, box: Box) -> tuple[list[Cred], list[Cred]]:
    """Return (recon_contexts, loot_contexts) of credentials for this box.

    recon = anonymous + best domain credential (admin preferred).
    loot  = only credentials that are admin on this box.
    """
    domain_creds: list[Cred] = []
    admin_here: list[Cred] = []
    for user in db._users:
        if user.domain is not box.domain:
            continue
        try:
            cred = Cred.from_user(user)
        except ValueError:
            continue
        domain_creds.append(cred)
        if box.hostname in user.admin_on:
            admin_here.append(cred)

    recon = list(admin_here or domain_creds[:1])
    recon.append(Cred.anonymous())
    return recon, admin_here


def sweep(db: DB, threads: int = 24) -> None:
    """Run the module registry across all hosts concurrently.

    Only the (slow, IO-bound) nxc calls run in parallel; results are folded
    into the DB on this thread, so ordering of `found vuln` lines stays sane.
    """
    tasks: list[tuple[Box, ModuleSpec, Cred, str]] = []
    for box in list(db._hosts.values()):
        recon_ctx, loot_ctx = _contexts(db, box)
        for spec in MODULES:
            if spec.name not in available(spec.proto):
                continue
            contexts = loot_ctx if spec.kind == 'loot' else recon_ctx[:1]
            for cred in contexts:
                key = f'sweep:{box.hostname}:{spec.name}:{cred.key()}'
                if db.store and db.store.is_done(key):
                    continue   # resume: this module already ran in this context
                tasks.append((box, spec, cred, key))

    if not tasks:
        return

    def work(task):
        box, spec, cred, key = task
        return box, spec, key, nxc(spec.proto, box.ip, cred, module=spec.name)

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(work, t) for t in tasks]
        with Progress('module sweep', total=len(futures)) as bar:
            for future in as_completed(futures):
                try:
                    box, spec, key, output = future.result()
                except Exception as e:
                    err(f'sweep: module run failed: {e}')
                    bar.update()
                    continue
                lines = _report_lines(output)
                if lines:
                    cve = f' {spec.cve}' if spec.cve else ''
                    info(f'{box.hostname} {spec.proto}/{spec.name} ({spec.title}{cve}):')
                    for ln in lines:
                        plain('      ' + ln)
                if spec.kind == 'loot':
                    _harvest_creds(db, box, spec.name, output)
                if db.store:
                    db.store.mark_done(key)
                bar.update()
