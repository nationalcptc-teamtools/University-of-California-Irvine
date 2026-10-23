#!/usr/bin/env python3
"""TOTP generator. Secret is supplied by the caller - nothing is hardcoded.

Accepts either a bare base32 secret or a full otpauth:// URI, and honours the
URI's algorithm/digits/period instead of assuming the defaults. That matters:
Google Authenticator hardcodes a 30s step and silently ignores period=, so a
token with a non-default period produces wrong codes in most phone apps.

Usage:
    totp.py JBSWY3DPEHPK3PXP
    totp.py 'otpauth://totp/Issuer:user@x?secret=JBSWY3DPEHPK3PXP&period=120'
    totp.py <secret> --period 120 --digits 6 --algorithm SHA1
    totp.py <secret> --at 1792113512        # code at a specific unix time
    totp.py <secret> --watch                # refresh until Ctrl-C
    echo <secret> | totp.py -               # read secret from stdin

Exit status is 0 on success, 1 on a bad secret or bad arguments.
"""
import argparse, base64, binascii, hashlib, hmac, struct, sys, time
from urllib.parse import urlparse, parse_qs, unquote

ALGOS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}


def normalize_b32(secret: str) -> bytes:
    """Uppercase, strip the separators people paste, pad to a multiple of 8."""
    s = secret.strip().replace(" ", "").replace("-", "").replace("_", "").upper()
    if not s:
        raise ValueError("empty secret")
    s += "=" * ((8 - len(s) % 8) % 8)
    try:
        key = base64.b32decode(s, casefold=True)
    except binascii.Error as e:
        raise ValueError(f"not valid base32: {e}") from None
    if not key:
        raise ValueError("secret decoded to zero bytes")
    return key


def parse_uri(uri: str) -> dict:
    """Pull secret/algorithm/digits/period out of an otpauth:// URI."""
    u = urlparse(uri)
    if u.scheme != "otpauth":
        raise ValueError("not an otpauth:// URI")
    if u.netloc.lower() != "totp":
        raise ValueError(f"unsupported OTP type {u.netloc!r} (this tool does totp only)")
    q = parse_qs(u.query)
    if "secret" not in q:
        raise ValueError("URI has no secret= parameter")
    label = unquote(u.path.lstrip("/"))
    issuer = q.get("issuer", [None])[0]
    if issuer is None and ":" in label:
        issuer = label.split(":", 1)[0]
    return {
        "secret": q["secret"][0],
        "algorithm": q.get("algorithm", ["SHA1"])[0].upper(),
        "digits": int(q.get("digits", ["6"])[0]),
        "period": int(q.get("period", ["30"])[0]),
        "label": label or None,
        "issuer": issuer,
    }


def totp(key: bytes, at: float, period: int, digits: int, algo) -> str:
    counter = int(at) // period
    mac = hmac.new(key, struct.pack(">Q", counter), algo).digest()
    off = mac[-1] & 0x0F                                    # RFC 4226 dynamic truncation
    code = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def render(key, now, period, digits, algo, algo_name, quiet=False):
    remain = period - (int(now) % period)
    cur = totp(key, now, period, digits, algo)
    if quiet:
        print(cur)
        return
    print(f"  algorithm : HMAC-{algo_name}, {digits} digits, {period}s step")
    print(f"  previous  : {totp(key, now - period, period, digits, algo)}")
    print(f"  CURRENT   : {cur}   (valid {remain}s more)")
    print(f"  next      : {totp(key, now + period, period, digits, algo)}")
    if period != 30:
        print(f"  if 30s    : {totp(key, now, 30, digits, algo)}   "
              f"<- what a period-ignoring app (Google Authenticator) would show")
        print(f"  note      : period is {period}s, not the default 30s. With the usual +/-1 "
              f"window\n              tolerance a code can be accepted for up to {period*3}s.")


def main() -> int:
    p = argparse.ArgumentParser(
        description="Generate TOTP codes from a supplied secret or otpauth:// URI.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Usage:")[1] if "Usage:" in __doc__ else None,
    )
    p.add_argument("secret", help="base32 secret, a full otpauth:// URI, or - to read stdin")
    p.add_argument("--period", type=int, help="seconds per code (default 30, or from URI)")
    p.add_argument("--digits", type=int, help="code length (default 6, or from URI)")
    p.add_argument("--algorithm", choices=sorted(ALGOS), help="HMAC hash (default SHA1, or from URI)")
    p.add_argument("--at", type=float, help="unix timestamp to generate for (default: now)")
    p.add_argument("--watch", action="store_true", help="keep printing as codes roll over")
    p.add_argument("-q", "--quiet", action="store_true", help="print only the current code")
    a = p.parse_args()

    raw = sys.stdin.read().strip() if a.secret == "-" else a.secret

    cfg = {"algorithm": "SHA1", "digits": 6, "period": 30, "label": None, "issuer": None}
    if raw.lower().startswith("otpauth://"):
        try:
            cfg.update(parse_uri(raw))
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
    else:
        cfg["secret"] = raw

    # explicit flags win over whatever the URI said
    for k in ("period", "digits", "algorithm"):
        if getattr(a, k) is not None:
            cfg[k] = getattr(a, k)

    if cfg["algorithm"] not in ALGOS:
        print(f"error: unsupported algorithm {cfg['algorithm']!r}", file=sys.stderr)
        return 1
    if cfg["period"] < 1 or not (6 <= cfg["digits"] <= 10):
        print("error: period must be >=1 and digits between 6 and 10", file=sys.stderr)
        return 1

    try:
        key = normalize_b32(cfg["secret"])
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    algo = ALGOS[cfg["algorithm"]]
    if not a.quiet:
        who = " / ".join(x for x in (cfg.get("issuer"), cfg.get("label")) if x)
        if who:
            print(f"  account   : {who}")
        print(f"  key       : {len(key)} bytes ({len(key)*8} bits)")

    if not a.watch:
        render(key, a.at if a.at is not None else time.time(),
               cfg["period"], cfg["digits"], algo, cfg["algorithm"], a.quiet)
        return 0

    try:
        last = None
        while True:
            now = time.time()
            code = totp(key, now, cfg["period"], cfg["digits"], algo)
            if code != last:
                remain = cfg["period"] - (int(now) % cfg["period"])
                print(f"  {time.strftime('%H:%M:%S')}  {code}  ({remain}s left)", flush=True)
                last = code
            time.sleep(0.5)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
