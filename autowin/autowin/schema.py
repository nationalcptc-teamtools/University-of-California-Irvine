import threading
from typing import Any, Literal, Iterator, TYPE_CHECKING
from dataclasses import dataclass, field
from .console import Colors, err, good, warn

if TYPE_CHECKING:
    from .store import Store

HashSource = Literal['asrep', 'kerberoast', 'timeroast', 'ntlm']


def _notable(pairs: dict[str, Any]) -> str:
    notable: list[str] = []
    for key, value in pairs.items():
        if isinstance(value, bool):
            if value:
                notable.append(f'({key})')
        elif isinstance(value, int):
            if value:                       # non-zero count: show the number
                notable.append(f'({key}: {value})')
        elif value:
            notable.append(f'({key})')

    return f' {Colors.RED}{" ".join(notable)}{Colors.RESET}' if len(notable) > 0 else ''


@dataclass
class Share:
    name: str
    owner: 'Box'
    description: str
    readable: bool = False
    writable: bool = False

    def __format__(self, format_spec: str) -> str:
        notable = _notable({'R': self.readable, 'W': self.writable})
        return f'smb://{self.owner.hostname}/{self.name}: {self.description}{notable}'


@dataclass
class Vuln:
    """A vulnerability / CVE / misconfiguration finding tied to a host."""
    title: str
    owner: 'Box'
    source: str                    # the nxc module name, 'certipy', 'impacket', ...
    cve: str | None = None
    detail: str | None = None
    esc: str | None = None         # ADCS ESC class, when applicable

    def key(self) -> tuple[str, str, str | None]:
        return (self.source, self.title, self.esc)

    def __format__(self, format_spec: str) -> str:
        tag = f'{Colors.RED}{self.cve}{Colors.RESET} ' if self.cve else ''
        esc = f'{Colors.RED}{self.esc}{Colors.RESET} ' if self.esc else ''
        detail = f': {self.detail}' if self.detail else ''
        return f'{self.owner.hostname} ({self.owner.ip}) {esc}{tag}{Colors.YELLOW}{self.title}{Colors.RESET}{detail}'


@dataclass
class Hash:
    source: HashSource
    hash: str

    def __format__(self, format_spec: str) -> str:
        return f'{self.source}: {self.hash}'


@dataclass
class Box:
    ip: str
    hostname: str
    domain: 'Domain'
    dc: bool
    signing: bool
    smbv1: bool
    smb_null_auth: bool
    os: str | None = None

    local_users: dict[str, 'User'] = field(default_factory=dict)
    local_shares: dict[str, 'Share'] = field(default_factory=dict)
    vulns: dict[tuple[str, str, str | None], 'Vuln'] = field(default_factory=dict)

    def __format__(self, format_spec: str) -> str:
        notable = _notable({
            'DC': self.dc,
            'Unsigned': not self.signing,
            'SMBv1': self.smbv1,
            'SMB Null Auth': self.smb_null_auth,
        })
        os = f' [{self.os}]' if self.os else ''
        return f'{self.hostname} ({self.ip}){os} (domain: {self.domain}){notable}'


@dataclass
class User:
    name: str
    owner: Box
    bad_pwd_count: int | None = None
    description: str | None = None
    hash: Hash | None = None
    password: str | None = None
    admin_on: set[str] = field(default_factory=set)   # hostnames where this user is Pwn3d! (SMB)
    winrm_on: set[str] = field(default_factory=set)   # hostnames where WinRM gives a shell
    verified: bool = False                            # creds confirmed to authenticate

    @property
    def domain(self) -> 'Domain':
        return self.owner.domain

    def update(self, user: 'User') -> bool:
        assert self.name == user.name

        updated = False

        if self.bad_pwd_count is None and user.bad_pwd_count is not None:
            self.bad_pwd_count = user.bad_pwd_count
            updated = True

        if self.description is None and user.description is not None:
            self.description = user.description
            updated = True

        if self.password is None and user.password is not None:
            self.password = user.password
            updated = True

        if self.hash is None and user.hash is not None:
            self.hash = user.hash
            updated = True

        if not user.admin_on.issubset(self.admin_on):
            self.admin_on |= user.admin_on
            updated = True

        if not user.winrm_on.issubset(self.winrm_on):
            self.winrm_on |= user.winrm_on
            updated = True

        if user.verified and not self.verified:
            self.verified = True
            updated = True

        return updated

    def shells(self) -> list[str]:
        kinds = []
        if self.admin_on:
            kinds.append('smb')
        if self.winrm_on:
            kinds.append('winrm')
        return kinds

    def __format__(self, format_spec: str) -> str:
        items = {
            'KRB hash': self.hash,
            'Password': self.password,
            'Bad PWDs': self.bad_pwd_count,
            'Admin': len(self.admin_on) > 0,
        }
        sh = self.shells()
        if sh:
            items[f'Shell: {",".join(sh)}'] = True
        notable = _notable(items)
        description = '(more privileged)' if self.description is None else self.description
        return f'{self.domain}\\{self.name}: {description}{notable}'


@dataclass
class Domain:
    name: str

    boxes: list[Box] = field(default_factory=list)
    dc: Box | None = None
    password_policy: dict[str, str] | None = None

    def __format__(self, format_spec: str) -> str:
        return f'{self.name}'


@dataclass
class DB:
    _hosts: dict[str, Box] = field(default_factory=dict)
    _domains: dict[str, Domain] = field(default_factory=dict)
    _users: list[User] = field(default_factory=list)

    store: 'Store | None' = None
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    # ---- lookups -------------------------------------------------------

    def domain(self, name: str) -> Domain:
        domain = self._domains.get(name.lower(), None)

        if domain is None:
            domain = Domain(name=name)
            self._domains[name.lower()] = domain

        return domain

    def boxes_in(self, domain: Domain) -> list[Box]:
        return [box for box in self._hosts.values() if box.domain is domain]

    def credentialed_users(self) -> list[User]:
        """Every user we can currently authenticate as (plaintext password)."""
        return [u for u in self._users if u.password is not None]

    def find_user(self, domain: Domain, name: str) -> User | None:
        for u in self._users:
            if u.owner.domain is domain and u.name.lower() == name.lower():
                return u
        return None

    def vulns(self) -> list[Vuln]:
        return [v for box in self._hosts.values() for v in box.vulns.values()]

    def signature(self) -> tuple[int, int, int, int, int]:
        """Fixpoint signature for the discovery loop: grows as we learn more."""
        users = len(self._users)
        creds = sum(1 for u in self._users if u.password is not None)
        hashes = sum(1 for u in self._users if u.hash is not None)
        admin = sum(len(u.admin_on) for u in self._users)
        vulns = len(self.vulns())
        return (users, creds, hashes, admin, vulns)

    # ---- mutation (locked; every insert reports once & write-throughs) --
    #
    # The lock makes the DB safe for the threaded recon and the parallel
    # module sweep, and keeps `good()` log lines from interleaving.

    def add_box(self, box: Box) -> bool:
        with self._lock:
            if box.hostname in self._hosts:
                return False

            self._hosts[box.hostname] = box
            box.domain.boxes.append(box)

            if box.dc:
                if box.domain.dc is not None and box.domain.dc is not box:
                    warn(f'found two dcs for domain {box.domain}: {box.hostname}, {box.domain.dc.hostname}')
                box.domain.dc = box

            good(f'found box {box}')
            if self.store:
                self.store.add_host(box.ip, box.hostname, box.domain.name, box.dc,
                                    box.signing, box.smbv1, box.smb_null_auth, box.os)
            return True

    def add_user(self, user: User) -> bool:
        with self._lock:
            existing_user = user.owner.local_users.get(user.name, None)

            if existing_user is None:
                user.owner.local_users[user.name] = user
                self._users.append(user)
                good(f'found user {user}')
                if self.store:
                    self.store.add_user(user.domain.name, user.name, user.description)
                if user.hash is not None:
                    self._persist_hash(user)
                if user.password is not None:
                    self._persist_cred(user, 'enum')
                return True

            updated = existing_user.update(user)
            if updated:
                good(f'updated user {existing_user}')
                if self.store:
                    self.store.add_user(existing_user.domain.name, existing_user.name,
                                        existing_user.description)
            return updated

    def add_share(self, share: Share) -> bool:
        with self._lock:
            if share.name in share.owner.local_shares:
                return False

            share.owner.local_shares[share.name] = share
            good(f'found share {share}')
            if self.store:
                perms = ('R' if share.readable else '') + ('W' if share.writable else '')
                self.store.add_share(share.owner.hostname, share.name, perms, share.description)
            return True

    def add_vuln(self, vuln: Vuln) -> bool:
        with self._lock:
            if vuln.key() in vuln.owner.vulns:
                return False

            vuln.owner.vulns[vuln.key()] = vuln
            good(f'found vuln {vuln}')
            if self.store:
                self.store.add_vuln(vuln.owner.hostname, vuln.source, vuln.title,
                                    vuln.cve, vuln.esc, vuln.detail)
            return True

    # ---- credential / hash discovery (persisted) -----------------------

    def set_hash(self, user: User, source: str, hash_value: str) -> bool:
        with self._lock:
            if user.hash is not None:
                return False
            user.hash = Hash(source=source, hash=hash_value)
            good(f'{source} hash for {user.domain}\\{user.name}')
            self._persist_hash(user)
            return True

    def set_password(self, user: User, password: str, source: str = '', host: str = '') -> bool:
        with self._lock:
            if user.password is not None:
                return False
            user.password = password
            good(f'credential {user.domain}\\{user.name}:{Colors.RED}{password}{Colors.RESET} ({source})')
            self._persist_cred(user, source, host)
            return True

    def _persist_hash(self, user: User) -> None:
        if self.store and user.hash is not None:
            self.store.add_hash(user.domain.name, user.name, user.hash.source, user.hash.hash)

    def _persist_cred(self, user: User, source: str, host: str = '') -> None:
        if self.store and user.password is not None:
            self.store.add_credential(user.domain.name, user.name, user.password,
                                      is_hash=False, source=source, host=host)

    # ---- reporting -----------------------------------------------------

    def report(self) -> None:
        print()
        print(f'{Colors.LIGHT_WHITE}{Colors.BOLD}==================== LOOT ===================={Colors.RESET}')

        for domain in self._domains.values():
            print(f'\n{Colors.LIGHT_CYAN}# domain {domain}{Colors.RESET}')
            for box in self.boxes_in(domain):
                print(f'  {box}')
            if domain.password_policy:
                print(f'  {Colors.LIGHT_WHITE}password policy:{Colors.RESET}')
                for key, value in domain.password_policy.items():
                    print(f'    {key}: {value}')

        creds = self.credentialed_users()
        print(f'\n{Colors.LIGHT_CYAN}# credentials ({len(creds)}){Colors.RESET}')
        for user in creds:
            secret = user.password if user.password is not None else '<hash>'
            shells = user.shells()
            tag = ''
            if shells:
                tag = f' {Colors.GREEN}(shell: {",".join(shells)}){Colors.RESET}'
            elif user.verified:
                tag = f' {Colors.GREEN}(verified){Colors.RESET}'
            print(f'  {user.domain}\\{user.name}:{Colors.RED}{secret}{Colors.RESET}{tag}')

        hashes = [u for u in self._users if u.hash is not None and u.password is None]
        print(f'\n{Colors.LIGHT_CYAN}# uncracked hashes ({len(hashes)}){Colors.RESET}')
        for user in hashes:
            print(f'  {user.domain}\\{user.name} ({user.hash.source})')

        vulns = self.vulns()
        print(f'\n{Colors.LIGHT_CYAN}# vulnerabilities ({len(vulns)}){Colors.RESET}')
        for vuln in vulns:
            print(f'  {vuln}')
        print()
