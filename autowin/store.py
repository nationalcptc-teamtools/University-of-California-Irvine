"""Persistent, engagement-scoped storage: a SQLite DB plus loot files.

Layout (default ./loot, override with --loot-dir):
    loot/
      autowin.sqlite        # credentials, users, hashes, hosts, shares, vulns, loot
      users.txt             # every discovered username (deduped, spray-ready)
      users_<domain>.txt    # per-domain username lists
      hashes/<source>.txt   # asrep.txt / kerberoast.txt / timeroast.txt / ntlm.txt
      bloodhound/           # collected BloodHound zips

Nothing here is environment-specific; it is a generic operator datastore.
"""
import os
import re
import sqlite3
import threading
import time
from pathlib import Path


def _slug(name: str) -> str:
    return re.sub(r'[^A-Za-z0-9._-]', '_', name) or 'unknown'


_SCHEMA = """
CREATE TABLE IF NOT EXISTS credentials (
    domain TEXT, username TEXT, secret TEXT, is_hash INTEGER DEFAULT 0,
    source TEXT, host TEXT, ts REAL,
    UNIQUE(domain, username, secret, is_hash));
CREATE TABLE IF NOT EXISTS users (
    domain TEXT, username TEXT, description TEXT, ts REAL,
    UNIQUE(domain, username));
CREATE TABLE IF NOT EXISTS hashes (
    domain TEXT, username TEXT, source TEXT, hash TEXT, ts REAL,
    UNIQUE(hash));
CREATE TABLE IF NOT EXISTS hosts (
    ip TEXT, hostname TEXT, domain TEXT, dc INTEGER, signing INTEGER,
    smbv1 INTEGER, null_auth INTEGER, os TEXT, ts REAL,
    UNIQUE(hostname));
CREATE TABLE IF NOT EXISTS shares (
    host TEXT, name TEXT, perms TEXT, remark TEXT, ts REAL,
    UNIQUE(host, name));
CREATE TABLE IF NOT EXISTS vulns (
    host TEXT, source TEXT, title TEXT, cve TEXT, esc TEXT, detail TEXT, ts REAL,
    UNIQUE(host, source, title, esc));
CREATE TABLE IF NOT EXISTS loot (
    host TEXT, module TEXT, domain TEXT, data TEXT, ts REAL,
    UNIQUE(host, module, data));
CREATE TABLE IF NOT EXISTS bloodhound (
    domain TEXT PRIMARY KEY, username TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS completed (
    key TEXT PRIMARY KEY, ts REAL);
"""


class Store:
    def __init__(self, loot_dir: str):
        self.dir = Path(loot_dir)
        self.hashes_dir = self.dir / 'hashes'
        self.bloodhound_dir = self.dir / 'bloodhound'
        for d in (self.dir, self.hashes_dir, self.bloodhound_dir):
            d.mkdir(parents=True, exist_ok=True)

        self.db = sqlite3.connect(str(self.dir / 'autowin.sqlite'), check_same_thread=False)
        self.db.isolation_level = None  # autocommit
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.executescript(_SCHEMA)
        self._lock = threading.Lock()

    # ---- helpers -------------------------------------------------------

    def _insert(self, sql: str, params: tuple) -> bool:
        """INSERT OR IGNORE; return True if a new row was actually added."""
        with self._lock:
            cur = self.db.execute(sql, params)
            return cur.rowcount == 1

    def _append_line(self, path: Path, line: str) -> None:
        with self._lock:
            with open(path, 'a', encoding='utf-8') as f:
                f.write(line.rstrip('\n') + '\n')

    # ---- writers (return True when newly stored) -----------------------

    def add_credential(self, domain, username, secret, is_hash=False, source='', host='') -> bool:
        return self._insert(
            'INSERT OR IGNORE INTO credentials VALUES (?,?,?,?,?,?,?)',
            (domain, username, secret, int(is_hash), source, host, time.time()))

    def add_user(self, domain, username, description=None) -> bool:
        is_new = self._insert(
            'INSERT OR IGNORE INTO users VALUES (?,?,?,?)',
            (domain, username, description, time.time()))
        if is_new and not username.endswith('$'):   # skip machine accts in spray lists
            self._append_line(self.dir / 'users.txt', username)
            self._append_line(self.dir / f'users_{_slug(domain)}.txt', username)
        return is_new

    def add_hash(self, domain, username, source, hash_value) -> bool:
        is_new = self._insert(
            'INSERT OR IGNORE INTO hashes VALUES (?,?,?,?,?)',
            (domain, username, source, hash_value, time.time()))
        if is_new:
            self._append_line(self.hashes_dir / f'{_slug(source)}.txt', hash_value)
        return is_new

    def add_host(self, ip, hostname, domain, dc, signing, smbv1, null_auth, os_) -> bool:
        return self._insert(
            'INSERT OR IGNORE INTO hosts VALUES (?,?,?,?,?,?,?,?,?)',
            (ip, hostname, domain, int(dc), int(signing), int(smbv1), int(null_auth), os_, time.time()))

    def add_share(self, host, name, perms, remark) -> bool:
        return self._insert('INSERT OR IGNORE INTO shares VALUES (?,?,?,?,?)',
                            (host, name, perms, remark, time.time()))

    def add_vuln(self, host, source, title, cve, esc, detail) -> bool:
        return self._insert('INSERT OR IGNORE INTO vulns VALUES (?,?,?,?,?,?,?)',
                            (host, source, title, cve, esc, detail, time.time()))

    def add_loot(self, host, module, domain, data) -> bool:
        return self._insert('INSERT OR IGNORE INTO loot VALUES (?,?,?,?,?)',
                            (host, module, domain, data, time.time()))

    # ---- bloodhound bookkeeping ---------------------------------------

    def bloodhound_done(self, domain) -> bool:
        with self._lock:
            row = self.db.execute('SELECT 1 FROM bloodhound WHERE domain=?', (domain,)).fetchone()
            return row is not None

    def mark_bloodhound(self, domain, username) -> None:
        with self._lock:
            self.db.execute('INSERT OR REPLACE INTO bloodhound VALUES (?,?,?)',
                            (domain, username, time.time()))

    # ---- resume bookkeeping (a step for a given context ran already) ---

    def is_done(self, key: str) -> bool:
        with self._lock:
            return self.db.execute('SELECT 1 FROM completed WHERE key=?', (key,)).fetchone() is not None

    def mark_done(self, key: str) -> None:
        with self._lock:
            self.db.execute('INSERT OR IGNORE INTO completed VALUES (?,?)', (key, time.time()))

    # ---- readers -------------------------------------------------------

    def list_credentials(self, domain=None) -> list[dict]:
        sql = 'SELECT domain,username,secret,is_hash,source,host FROM credentials'
        args: tuple = ()
        if domain:
            sql += ' WHERE domain=?'
            args = (domain,)
        with self._lock:
            rows = self.db.execute(sql, args).fetchall()
        return [{'domain': r[0], 'username': r[1], 'secret': r[2],
                 'is_hash': bool(r[3]), 'source': r[4], 'host': r[5]} for r in rows]

    def list_users(self, domain=None) -> list[dict]:
        sql = 'SELECT domain,username,description FROM users'
        args: tuple = ()
        if domain:
            sql += ' WHERE domain=?'
            args = (domain,)
        with self._lock:
            rows = self.db.execute(sql, args).fetchall()
        return [{'domain': r[0], 'username': r[1], 'description': r[2]} for r in rows]

    def list_hosts(self) -> list[dict]:
        with self._lock:
            rows = self.db.execute(
                'SELECT ip,hostname,domain,dc,signing,smbv1,null_auth,os FROM hosts').fetchall()
        return [{'ip': r[0], 'hostname': r[1], 'domain': r[2], 'dc': bool(r[3]),
                 'signing': bool(r[4]), 'smbv1': bool(r[5]), 'null_auth': bool(r[6]),
                 'os': r[7]} for r in rows]

    def list_hashes(self) -> list[dict]:
        with self._lock:
            rows = self.db.execute('SELECT domain,username,source,hash FROM hashes').fetchall()
        return [{'domain': r[0], 'username': r[1], 'source': r[2], 'hash': r[3]} for r in rows]

    def list_shares(self) -> list[dict]:
        with self._lock:
            rows = self.db.execute('SELECT host,name,perms,remark FROM shares').fetchall()
        return [{'host': r[0], 'name': r[1], 'perms': r[2], 'remark': r[3]} for r in rows]

    def list_vulns(self) -> list[dict]:
        with self._lock:
            rows = self.db.execute('SELECT host,source,title,cve,esc,detail FROM vulns').fetchall()
        return [{'host': r[0], 'source': r[1], 'title': r[2], 'cve': r[3],
                 'esc': r[4], 'detail': r[5]} for r in rows]

    def close(self) -> None:
        with self._lock:
            self.db.close()
