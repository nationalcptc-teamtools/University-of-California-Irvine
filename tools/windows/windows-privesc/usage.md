# Windows privilege escalation — what's here and when to use it

Usage for every tool is in its upstream project. This file records the thing that
is slow to work out on the box: **which tool applies to which host, and what has
to already be true for it to work.**

Claims are marked **[upstream]** where they come from the author's own
documentation and **[verified]** where they were checked against the binary in
this directory. See [Provenance](#provenance) for how.

---

## `potato/` and `printspoofer/` — SeImpersonatePrivilege

A service identity holding `SeImpersonatePrivilege` — commonly IIS, MSSQL and
similar service accounts — can be escalated to `NT AUTHORITY\SYSTEM`. Every tool
below exploits that same privilege. They differ only in the OS mechanism they go
through, and each mechanism was closed off at a different point. Carrying several
is coverage, not duplication.

Check the privilege is actually present before spending time here; if it isn't,
none of these apply.

### Pick by what the host gives you

| Host situation | Use | Why |
|---|---|---|
| Server 2012–2022, Win 8–11, .NET available | **GodPotato** | Widest coverage. Goes through `rpcss`, which is always running, so there is no service to be switched off |
| Print Spooler running, **no .NET** on the box | **PrintSpoofer** | Native binaries — the only option here that needs no .NET runtime |
| GodPotato unavailable, EFSRPC reachable | **EfsPotato** | Separate mechanism (MS-EFSR), and has alternate pipes to fall back through |
| Server ≤2016, or Win 10 ≤1803 | **JuicyPotato** | The only place it still works — and the only one of these that covers pre-2012 |
| Hardened 2019+: spooler disabled **and** EFSRPC patched | **GodPotato** | This is the gap the other three leave |

Rough order to try on an unknown modern host: GodPotato → PrintSpoofer (if the
spooler is up) → EfsPotato. On anything that looks legacy, start with
JuicyPotato instead.

### GodPotato — `potato/GodPotato-NET4.exe`, `potato/GodPotato-NET35.exe`

- **Applies to:** Windows Server 2012–2022, Windows 8–11 **[upstream]**
- **Needs:** `SeImpersonatePrivilege`, and a matching .NET runtime
- **Mechanism:** a defect in how `rpcss` handles OXID resolution **[upstream]**.
  `rpcss` is a service Windows must run, which is why this works where the
  spooler- and EFSRPC-based tools don't.
- **Which build:** `NET4` targets CLR `v4.0.30319`; `NET35` targets CLR
  `v2.0.50727` and covers both .NET 2.0 and 3.5 **[verified]**. Use `NET4` by
  default — Server 2012 and later ship .NET 4.x — and `NET35` only on a host
  without .NET 4.
- **Architecture:** both are AnyCPU (`ILONLY`, no `32BITREQUIRED`), so a single
  file runs natively as 64-bit on x64 **[verified]**. There is no separate
  32/64-bit build to pick.
- Upstream ships a third asset, `GodPotato-NET2.exe`. It is **byte-identical** to
  `GodPotato-NET35.exe` **[verified]**, so only one of the two is kept here.
- Pinned to release `V1.20` (2023-04-11), Apache-2.0.

### PrintSpoofer — `printspoofer/PrintSpoofer32.exe`, `printspoofer/PrintSpoofer64.exe`

- **Applies to:** Windows 10 and Server 2016/2019 **[upstream]**. The author does
  not claim Server 2022.
- **Needs:** the **Print Spooler service running**. Since PrintNightmare the
  spooler is frequently disabled on servers — check before relying on this.
- **Mechanism:** abuses the Print Spooler to obtain a SYSTEM token **[upstream]**.
- **Architecture:** native executables, not .NET — `PrintSpoofer32.exe` is PE32
  (x86) and `PrintSpoofer64.exe` is PE32+ (x64) **[verified]**. Match the build
  to the host. Being native is the real advantage: it is the only tool here that
  works on a box with no .NET runtime at all.
- Upstream repository is **archived** (last push 2020-09-10), so expect no fixes
  and no support for newer Windows.

### EfsPotato — `potato/EfsPotato.exe`

- **Needs:** `SeImpersonatePrivilege` and a reachable MS-EFSR endpoint.
- **Mechanism:** MS-EFSR `EfsRpcEncryptFileSrv` **[upstream]**.
- **Fallbacks:** upstream accepts an alternate named pipe —
  `lsarpc`, `efsrpc`, `samr`, `lsass` or `netlogon`, default `lsarpc`
  **[upstream]**. This matters, because the individual pipes have been hardened
  at different times: if the default is closed, another may still answer. If one
  pipe fails, try the others before concluding the host is not vulnerable.
- **Architecture:** our copy is the **x86-only** .NET 4 build
  (`32BITREQUIRED`) **[verified]**, so on x64 it runs under WOW64. That is
  normally fine, but it will not run where WOW64 is absent. Upstream is
  distributed as source and can be built AnyCPU if we ever need that.
- No license file upstream. Last upstream push 2023-12-14.

### JuicyPotato — `potato/JuicyPotato.exe`, `potato/Lovely-Potato/JuicyPotato-Static.exe`

- **Applies to:** Server ≤2016 and Windows 10 ≤1803 only. **It does not work on
  Windows 10 1809 / Server 2019 or later.**
- **Needs:** `SeImpersonatePrivilege` and a usable CLSID on the host.
  `Lovely-Potato/test_clsid.bat` enumerates candidates.
- **Keep it anyway.** Legacy Windows is very plausible on an OT or
  industrial-adjacent estate — old HMI boxes and 2012R2 front-ends are exactly
  where this still works, and it is the only tool here that reaches back that far.
- Both binaries are PE32+ (x64) and 347,648 bytes, but they are **different
  builds with different hashes** **[verified]** — `JuicyPotato-Static.exe` came
  with the Lovely-Potato clone.

### `potato/Lovely-Potato/` — wrapper, needs configuring

A PowerShell wrapper around JuicyPotato that automates CLSID enumeration. Three
things to know before using it:

1. `$RemoteDir` in `Invoke-LovelyPotato.ps1` is a **placeholder** holding
   upstream's own lab address. It has to be set to our staging host.
2. The script **calls itself on its last line**. That is deliberate — upstream's
   documented invocation loads it remotely and expects it to run on load — but it
   means loading the file executes it immediately.
3. It expects a payload named `meterpreter.exe` alongside it, which **has to be
   generated per engagement** so it points at our own listener. One cannot be
   usefully committed here, and a stale one is worse than none. One was removed
   from this directory for that reason.

CLSID enumeration takes around ten minutes before anything happens. On a clock,
prefer a tool from the table above.

### Not carried here

Worth knowing these exist if the four above all fail:

| Tool | Note |
|---|---|
| **RoguePotato** | Covers 2019+, but needs a redirector using port 135 as its source port **[upstream]** — extra infrastructure. GPL-3.0, last push 2021-01. |
| **JuicyPotatoNG** | Revived JuicyPotato with firewall-aware COM port selection. MIT, last push 2022-11. |
| **SigmaPotato** | GodPotato derivative; adds loading from memory via .NET reflection. Apache-2.0, last push 2024-05 — more recently maintained than GodPotato itself. Worth considering if on-disk binaries become a problem. |
| **SweetPotato** | Windows 7 → Windows 10 / Server 2019 **[upstream]**. No license file. |
| **SharpEfsPotato** | Another EfsRpc-based variant. |

---

## `backup_priv/` — SeBackupPrivilege

`SeBackupPrivilegeCmdLets.dll` and `SeBackupPrivilegeUtils.dll`. A different
privilege entirely — `SeBackupPrivilege` grants read access that bypasses file
ACLs. Relevant where an account is in Backup Operators or holds the privilege
directly. Not an alternative to the tools above; it does not give SYSTEM.

## `winpeas/` — enumeration, not escalation

`winPEASx64.exe`, `winPEASx86.exe`, `winPEASany.exe` and `winPEAS.bat`. Run
these **first** to find out which privilege you actually have; they tell you
whether anything in this directory applies. `winPEAS.bat` is the fallback where
.NET is unavailable.

Note: all stock builds, so expect Defender to flag them on sight.

---

## Provenance

| File | Bytes | SHA-256 |
|---|---|---|
| `potato/GodPotato-NET4.exe` | 57,344 | `9a8e9d587b570d4074f1c8317b163aa8d0c566efd88f294d9d85bc7776352a28` |
| `potato/GodPotato-NET35.exe` | 57,344 | `3027a212272957298bf4d32505370fa63fb162d6a6a6ec091af9d7626317a858` |
| `potato/EfsPotato.exe` | 17,920 | `d8527df2231826af6489835c7229528892a10f29ef182c957979e758c0d230a3` |
| `potato/JuicyPotato.exe` | 347,648 | `0f56c703e9b7ddeb90646927bac05a5c6d95308c8e13b88e5d4f4b572423e036` |
| `potato/Lovely-Potato/JuicyPotato-Static.exe` | 347,648 | `67e077d1d01362f7d830910aa88b6e94049eb32d3c2668827582f05ee75657c3` |
| `printspoofer/PrintSpoofer32.exe` | 22,016 | `47c9eff8142490a2c341701aab7aaebc355eed1540eed534a8317dd1e65614b2` |
| `printspoofer/PrintSpoofer64.exe` | 27,136 | `8524fbc0d73e711e69d60c64f1f1b7bef35c986705880643dd4d5e17779e586d` |

GodPotato was fetched from the **pinned** release tag, not `releases/latest`:

    https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe
    https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET35.exe

A floating URL with a fixed hash is not a pin — it fails the moment upstream cuts
a release, and a check that cries wolf gets ignored.

**How the [verified] claims were checked:** `.NET` runtime target and AnyCPU vs
32-bit from the PE CLI header flags (`ILONLY` / `32BITREQUIRED`); architecture
from the PE optional-header magic; byte-identity and the hashes above from
`sha256sum`. Nothing in this directory was executed.

Upstream sources: `BeichenDream/GodPotato`, `itm4n/PrintSpoofer`,
`zcgonvh/EfsPotato`, `ohpe/juicy-potato`, `TsukiCTF/Lovely-Potato`.
