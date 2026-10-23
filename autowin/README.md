# autowin-new

### Automated Active Directory vulnerability discovery

Recons an AD environment, enumerates it, roasts and cracks, then sweeps
NetExec's vuln/CVE/loot modules and Certipy for ADCS flaws — re-running the
whole sweep every time new users or credentials land in its database, until the
picture converges. The first valid credential per domain also kicks off a
one-shot BloodHound collection. Everything is saved to a persistent loot store.

Takes the functionality of [AutoWin](https://github.com/Drew-Levy/autoWin) and
rebuilds it in the typed-DB, pipeline style of
[autowin-mackenzie](../autowin-mackenzie): a single target range in, a loot
report out.

> [!WARNING]
> For **authorized** red-team engagements, CTFs, and lab environments
> only. Don't point it at anything you don't own or aren't contracted to test.

---

### How it works

Discovery is one automated, iterative loop (mackenzie-style — no attack flags):

```
recon ──► enumerate users/shares ──► as-rep roast ──► crack hashes
  ▲                                                          │
  └───────── re-scan while the DB keeps growing ◄───────────┤
                                                             ▼
   authed enumeration + kerberoast + bloodhound + admin map     vuln sweep
   (first valid cred per domain)                 (parallel NetExec modules)
                                                 + Certipy ADCS + delegation
```

Everything feeds a typed DB (`schema.py`): `Box`, `User`, `Share`, `Hash`,
`Vuln`, keyed by `Domain`. Each new fact is reported once (`found …` /
`updated …`) and **persisted to the loot store**; when a round adds anything new
the (thread-parallel) module sweep runs again — so a cracked hash or a loot
credential immediately re-opens authenticated attacks.

**Password spraying is not part of this loop** — it is risky (lockouts) and
runs only when you invoke the `spray` subcommand explicitly.

### The loot store (persistent)

Every run reads and writes `--loot-dir` (default `./loot`), so knowledge
accumulates across runs and credentials you add by hand are picked up:

```
loot/
  autowin.sqlite        credentials, users, hashes, hosts, shares, vulns, bloodhound, progress
  users.txt             every username found (spray-ready); users_<domain>.txt per domain
  hashes/<source>.txt   asrep.txt / kerberoast.txt / timeroast.txt — hashcat-ready
  bloodhound/           collected BloodHound zips
```

Runs **resume by default**: a re-run reloads the store and **skips every step
already completed** for the same context (recon, per-host enumeration, the
module sweep, roasting, ADCS/delegation, BloodHound). New credentials still
trigger new authenticated work. To start over, **delete `autowin.sqlite`** (or
the whole loot dir); `--rescan` forces a fresh network scan only.

### Requirements

- Python 3.11+ (standard library only — the tool drives external binaries)
- [NetExec](https://github.com/Pennyw0rth/NetExec) (`nxc`) — **required**
- [hashcat](https://hashcat.net) v6/v7 — optional (`--no-crack` to skip)
- [Certipy](https://github.com/ly4k/Certipy) (`certipy`) — for ADCS
- [Impacket](https://github.com/fortra/impacket) scripts (`findDelegation.py`,
  `rbcd.py`, `addcomputer.py`, `getST.py`) — for delegation discovery / RBCD
- [pyGPOAbuse](https://github.com/Hackndo/pyGPOAbuse) — only for `gpo`

### Usage

**Discovery** (the default — bare range works too):

```bash
python3 main.py 192.168.56.0/24
python3 main.py 192.168.56.0/24 --exclude 192.168.56.100          # skip a jumpbox
python3 main.py 192.168.56.10-23 --wordlist /usr/share/wordlists/rockyou.txt
python3 main.py 10.0.0.5 --no-crack --max-rounds 5 --timeroast
python3 main.py 10.0.0.0/24 --userlist candidate_users.txt        # kerbrute a candidate list
```

**Candidate username list** (`--userlist`): discovery validates each candidate
against the KDC (via `kerbrute` if installed, else `nmap krb5-enum-users`) and
folds only the **confirmed** usernames into the DB — so they then get AS-REP
roasted, written to `users.txt`, and are available to spray. Lines may be
`user`, `DOMAIN\user`, or `user@domain`.

`--exclude` takes an IP / CIDR / `a.b.c.d-e` range / list, and drops those hosts
from the scan (e.g. a jumpbox or out-of-scope address). `--loot-dir DIR` points
at a specific store (reused across runs).

**Credentials** — add ones you found elsewhere; discovery reuses them next run:

```bash
python3 main.py cred add -d domain.local -u user -p Passw0rd
python3 main.py cred add -d domain.local -u user -H <NTLM-hash>
python3 main.py cred list
```

**Password spray** (explicit, never automatic — defaults to the stored user
list, so after a `--userlist` discovery run it sprays exactly the validated
users). A **candidate password file** goes here via `--passwords`:

```bash
python3 main.py spray dc.domain.local -d domain.local --password-equals-username
python3 main.py spray dc.domain.local -d domain.local --passwords candidate_passwords.txt
python3 main.py spray dc.domain.local -d domain.local --users users.txt -p 'Spring2025!'
```

**Exploitation** (opt-in, one exploit per invocation — never run automatically):

```bash
# ADCS — auto-detect the ESC path, or force one
python3 main.py adcs 192.168.56.11 -d domain.local -u user -p pass --esc ESC1 --target ca.domain.local

# Resource-Based Constrained Delegation (and cleanup)
python3 main.py rbcd dc.domain.local -d domain.local -u user -p pass --target victim$
python3 main.py rbcd dc.domain.local -d domain.local -u user -p pass --target victim$ --clean

# Code execution through an editable GPO (you supply the command)
python3 main.py gpo -d domain.local -u user -p pass --gpo-id <GUID> --command "whoami"
```

Persistence techniques are intentionally **not** included.
