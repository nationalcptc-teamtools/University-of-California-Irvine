#!/usr/bin/env python3
"""
NCFuzz - fuzz a line-oriented TCP (or UDP) service.

For the menu-driven daemon on a weird port: connect, walk a couple of menu
levels, then push a wordlist through one field and see which answer is not
like the others.

Two things it does that save you the usual grief. Payloads are newline
terminated and backslash escapes are decoded, because a service reading lines
never answers anything you do not terminate. And responses are grouped by
shape rather than dumped, because with a 200k wordlist the finding is the rare
signature, not the transcript - so that is what the summary puts first.
"""

import argparse
import hashlib
import json
import re
import select
import socket
import sys
import time

VERSION = "2.0"

FUZZ = b"{FUZZ}"
PRINTABLE = range(32, 127)


# --------------------------------------------------------------------- helpers

def die(msg, code=1):
    print("[!] %s" % msg, file=sys.stderr)
    sys.exit(code)


def unescape(text):
    """Decode \\n, \\r, \\t, \\xNN in a command-line argument into bytes.

    A payload typed as '...\\r\\n' arrives here as a literal backslash, r,
    backslash, n - the shell does not interpret those inside normal quotes.
    Sending them raw is why the old version could never speak HTTP.
    """
    try:
        return text.encode("utf-8").decode("unicode_escape").encode("latin-1")
    except (UnicodeDecodeError, UnicodeEncodeError) as e:
        die("cannot decode escapes in %r: %s (use --no-escape to send it verbatim)" % (text, e))


def to_bytes(text, decode_escapes=True):
    return unescape(text) if decode_escapes else text.encode("utf-8", "surrogateescape")


def show(data, width=0):
    """One-line printable rendering of bytes, for the attempt column."""
    out = []
    for b in data:
        if b in PRINTABLE:
            out.append(chr(b))
        elif b == 0x0A:
            out.append("\\n")
        elif b == 0x0D:
            out.append("\\r")
        elif b == 0x09:
            out.append("\\t")
        else:
            out.append("\\x%02x" % b)
    s = "".join(out)
    if width and len(s) > width:
        s = s[:width - 3] + "..."
    return s


def parse_target(spec):
    """host:port, or [::1]:port for a literal IPv6 address."""
    if spec.startswith("["):
        host, _, rest = spec[1:].partition("]")
        if not rest.startswith(":"):
            die("bad target %r - use [%s]:port for IPv6" % (spec, host or "::1"))
        port = rest[1:]
    elif spec.count(":") == 1:
        host, _, port = spec.partition(":")
    else:
        die("bad target %r - use host:port (or [::1]:port for IPv6)" % spec)
    if not host:
        die("bad target %r - no host" % spec)
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        die("bad target %r - port must be 1-65535" % spec)
    return host, int(port)


def parse_sequence(values, decode_escapes):
    """Build the list of lines for -s / -r.

    -s is repeatable, which is the clear way to write it. A single argument in
    the old quoted-list form, -s "'2', '2'", is still understood so existing
    notes keep working.
    """
    out = []
    for v in values:
        stripped = v.strip()
        if len(values) == 1 and stripped.startswith("'") and stripped.endswith("'") and "'," in stripped.replace(" ", ""):
            out.extend(to_bytes(p, decode_escapes)
                       for p in re.findall(r"'((?:[^'\\]|\\.)*)'", stripped))
        else:
            out.append(to_bytes(v, decode_escapes))
    return out


def parse_lengths(spec):
    """'100-3000:100' -> 100, 200, ... 3000.  '1-50' -> 1..50."""
    m = re.fullmatch(r"(\d+)-(\d+)(?::(\d+))?", spec.strip())
    if not m:
        die("bad --lengths %r - use START-END[:STEP], e.g. 100-3000:100" % spec)
    lo, hi = int(m.group(1)), int(m.group(2))
    step = int(m.group(3) or 1)
    if lo > hi or step < 1:
        die("bad --lengths %r - need START <= END and STEP >= 1" % spec)
    return range(lo, hi + 1, step)


def load_payloads(args):
    """Yield (payload_bytes, label) pairs from a wordlist, stdin or --lengths."""
    if args.lengths:
        pattern = to_bytes(args.pattern, not args.no_escape) or b"A"
        for n in parse_lengths(args.lengths):
            blob = (pattern * (n // len(pattern) + 1))[:n]
            yield blob, "%s*%d" % (show(pattern, 8), n)
        return

    if args.wordlist == "-":
        raw = sys.stdin.buffer.read()
    else:
        try:
            with open(args.wordlist, "rb") as fh:
                raw = fh.read()
        except OSError as e:
            die("cannot read wordlist: %s" % e)

    seen_any = False
    for line in raw.split(b"\n"):
        line = line.rstrip(b"\r")
        if not line:
            continue
        seen_any = True
        yield line, show(line)
    if not seen_any:
        die("wordlist %s has no entries" % args.wordlist)


# ------------------------------------------------------------------ connection

class Target:
    """One socket to the service, with the reads and writes we need."""

    def __init__(self, host, port, udp=False, connect_timeout=5.0):
        self.host, self.port, self.udp = host, port, udp
        self.connect_timeout = connect_timeout
        self.sock = None

    def connect(self):
        kind = socket.SOCK_DGRAM if self.udp else socket.SOCK_STREAM
        try:
            infos = socket.getaddrinfo(self.host, self.port, 0, kind)
        except OSError as e:
            raise OSError("cannot resolve %s: %s" % (self.host, e))
        last = None
        for af, st, proto, _canon, sa in infos:
            s = socket.socket(af, st, proto)
            try:
                s.settimeout(self.connect_timeout)
                s.connect(sa)
                s.setblocking(False)
                self.sock = s
                return
            except OSError as e:
                last = e
                s.close()
        raise last

    def send(self, data):
        """True if it went out; False means the connection is gone."""
        if self.sock is None:
            return False
        try:
            self.sock.setblocking(True)
            self.sock.sendall(data)
            self.sock.setblocking(False)
            return True
        except OSError:
            self.close()
            return False

    def read(self, first_wait, settle, cap, until=None):
        """Collect a response.

        Wait up to first_wait for the first byte; once something arrives, keep
        reading until settle seconds of silence, until `until` matches, or
        until cap seconds have passed overall. Returns (data, closed).
        """
        if self.sock is None:
            return b"", True
        buf = b""
        start = time.monotonic()
        last = start
        while True:
            now = time.monotonic()
            if now - start >= cap:
                break
            if buf:
                budget = settle - (now - last)
            else:
                budget = first_wait - (now - start)
            if budget <= 0:
                break
            try:
                ready, _, _ = select.select([self.sock], [], [], min(budget, cap - (now - start)))
            except OSError:
                return buf, True
            if not ready:
                continue
            try:
                chunk = self.sock.recv(65536)
            except BlockingIOError:
                continue
            except OSError:
                self.close()
                return buf, True
            if not chunk:
                self.close()
                return buf, True
            buf += chunk
            last = time.monotonic()
            if until is not None and until.search(buf):
                break
        return buf, False

    def close(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None


# -------------------------------------------------------------------- triage

class Triage:
    """Groups responses by shape so the odd one out is easy to see.

    The payload is removed from the response before hashing: a service that
    echoes what you sent would otherwise make every single reply unique, and
    nothing would ever group.
    """

    def __init__(self):
        self.groups = {}
        self.order = []

    def signature(self, payload, response, closed):
        norm = response
        if len(payload) >= 2:
            norm = norm.replace(payload, b"")
        digest = hashlib.sha1(norm).hexdigest()[:8]
        return ("eof" if closed else "ok", len(norm), digest)

    def add(self, sig, label, response):
        g = self.groups.get(sig)
        if g is None:
            g = {"count": 0, "examples": [], "preview": show(response[:400], 64)}
            self.groups[sig] = g
            self.order.append(sig)
            first = True
        else:
            first = False
        g["count"] += 1
        if len(g["examples"]) < 3:
            g["examples"].append(label)
        return first

    def report(self, out=sys.stdout):
        if not self.groups:
            return
        ranked = sorted(self.order, key=lambda s: (self.groups[s]["count"], self.order.index(s)))
        total = sum(g["count"] for g in self.groups.values())
        print("\n%d response%s, %d distinct shape%s - rarest first:"
              % (total, "" if total == 1 else "s",
                 len(ranked), "" if len(ranked) == 1 else "s"), file=out)
        print("  %5s  %6s  %-12s  %-24s  %s"
              % ("count", "len", "sig", "example payload", "response"), file=out)
        for sig in ranked:
            g = self.groups[sig]
            state, length, digest = sig
            print("  %5d  %6d  %-12s  %-24s  %s"
                  % (g["count"], length, digest + ("/eof" if state == "eof" else ""),
                     (g["examples"][0] or "")[:24], g["preview"][:64]), file=out)
        if len(ranked) > 1 and self.groups[ranked[0]]["count"] == 1:
            print("\n[*] one-off response from: %s" % ", ".join(self.groups[ranked[0]]["examples"]),
                  file=out)


# ---------------------------------------------------------------------- fuzzing

def run(args):
    host, port = parse_target(args.target)
    esc = not args.no_escape

    template = to_bytes(args.payload, esc)
    if FUZZ not in template:
        die("-p/--payload must contain {FUZZ} - that is where each entry goes")

    eol = b"" if args.no_newline else (b"\r\n" if args.crlf else b"\n")
    prologue = parse_sequence(args.initial or [], esc)
    separator = parse_sequence(args.repeat or [], esc)
    until = re.compile(to_bytes(args.until, esc)) if args.until else None

    if separator and args.reconnect:
        die("-r/--repeat makes no sense with --reconnect: every attempt gets a fresh connection")

    payloads = list(load_payloads(args))
    target = Target(host, port, args.udp, args.connect_timeout)
    triage = Triage()
    journal = None
    if args.output:
        try:
            journal = open(args.output, "w", encoding="utf-8")
        except OSError as e:
            die("cannot write %s: %s" % (args.output, e))

    read_args = dict(first_wait=args.timeout, settle=args.settle, cap=args.max_read, until=until)
    quick = dict(first_wait=args.settle, settle=args.settle, cap=args.max_read, until=until)

    def open_connection():
        """Connect, swallow the banner, replay the prologue. None on failure."""
        for attempt in range(args.retries + 1):
            try:
                target.connect()
                break
            except OSError as e:
                if attempt == args.retries:
                    return "cannot connect: %s" % e
                time.sleep(0.5 * (attempt + 1))
        banner, _closed = target.read(**quick)
        if banner and args.verbose:
            print("[banner] %s" % show(banner, 200))
        for line in prologue:
            if not target.send(line + eol):
                return "connection dropped while sending the prologue"
            target.read(**quick)
        return None

    wide = max(len(str(len(payloads))), 2)
    print("[*] %s:%d %s | %d payload%s | %s"
          % (host, port, "udp" if args.udp else "tcp", len(payloads),
             "" if len(payloads) == 1 else "s",
             "reconnect each attempt" if args.reconnect else "one persistent connection"))
    if prologue:
        print("[*] prologue: %s" % " -> ".join(show(p, 20) for p in prologue))
    if until:
        print("[*] reading until /%s/ matches" % args.until)
    print()

    sent = 0
    down_after = None
    interrupted = False

    try:
        for index, (value, label) in enumerate(payloads, 1):
            payload = template.replace(FUZZ, value)

            if target.sock is None:
                problem = open_connection()
                if problem:
                    down_after = (index, label, problem)
                    if not args.keep_going:
                        break
                    print("%s  %-28s  %s" % (str(index).rjust(wide) + "/" + str(len(payloads)),
                                             label[:28], "DOWN - " + problem))
                    continue

            if separator and sent:
                for line in separator:
                    target.send(line + eol)
                target.read(**quick)

            began = time.monotonic()
            if not target.send(payload + eol):
                down_after = (index, label, "connection closed on send")
                if not args.keep_going:
                    break
                continue
            response, closed = target.read(**read_args)
            elapsed = time.monotonic() - began
            sent += 1

            if args.reconnect:
                target.close()

            sig = triage.signature(payload, response, closed)
            novel = triage.add(sig, label, response)

            if journal:
                journal.write(json.dumps({
                    "n": index,
                    "payload": label,
                    "sent": payload.decode("latin-1"),
                    "response": response.decode("latin-1"),
                    "bytes": len(response),
                    "ms": round(elapsed * 1000, 1),
                    "closed": closed,
                    "sig": sig[2],
                    "new": novel,
                }) + "\n")

            text = response.decode("latin-1")
            if args.match and not re.search(args.match, text):
                continue
            if args.hide and re.search(args.hide, text):
                continue
            if args.only_new and not novel:
                continue

            flags = []
            if novel and index > 1:
                flags.append("NEW")
            if closed:
                flags.append("EOF")
            if not response:
                flags.append("silent")

            print("%s/%d  %-28s  %5dB  %6.0fms  %s"
                  % (str(index).rjust(wide), len(payloads), label[:28],
                     len(response), elapsed * 1000, " ".join(flags)))

            if args.verbose or (novel and not args.quiet):
                for line in response.split(b"\n"):
                    if line.strip():
                        print("      | %s" % show(line, 0 if args.verbose else 100))

            if args.delay:
                time.sleep(args.delay)

    except KeyboardInterrupt:
        interrupted = True
        print("\n[*] interrupted after %d of %d" % (sent, len(payloads)))
    finally:
        target.close()
        if journal:
            journal.close()

    triage.report()
    if journal:
        print("[*] full transcript: %s" % args.output)

    if down_after and not args.keep_going:
        index, label, problem = down_after
        print("\n[!] service stopped answering at payload %d of %d (%s): %s"
              % (index, len(payloads), label, problem))
        print("[!] that payload is the finding - confirm it on its own with:")
        print("      printf '%%s\\n' %s | %s %s -w - --reconnect"
              % (repr(label), sys.argv[0], args.target))
        print("[!] use --keep-going to push through the rest of the wordlist instead.")
        return 3
    return 2 if interrupted else 0


def main():
    parser = argparse.ArgumentParser(
        prog="NCFuzz.py",
        description="Fuzz one field of a line-oriented TCP/UDP service.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples
  the common case - one wordlist into a service that just reads a line
    %(prog)s 10.10.10.5:9999 -w wordlists/big.txt

  walk a menu first, then fuzz the field it lands on
    %(prog)s 10.10.10.5:9999 -w ids.txt -s 2 -s 1

  password prompt - stop reading the moment the prompt comes back, which is
  what makes a big wordlist finish this year
    %(prog)s 10.10.10.5:9999 -w rockyou.txt -s login -s admin --until 'password:'

  speak HTTP by hand (escapes are decoded, so this one actually works)
    %(prog)s 10.10.10.5:80 -w dirs.txt --reconnect --no-newline \\
      -p 'GET /{FUZZ} HTTP/1.1\\r\\nHost: target\\r\\nConnection: close\\r\\n\\r\\n'

  look for an overflow: 100 to 3000 bytes of A, fresh connection each time
    %(prog)s 10.10.10.5:9999 --lengths 100-3000:100 --reconnect

  keep the evidence for the report
    %(prog)s 10.10.10.5:9999 -w names.txt -o fuzz.jsonl

reading the output
  one line per attempt with the response size and how long it took, then a
  summary that groups responses by shape and puts the rarest first. NEW marks
  a shape not seen before and prints it; EOF means the service hung up.

exit codes
  0 finished   2 interrupted   3 the service stopped answering   1 bad usage
""")

    parser.add_argument("target", help="host:port (or [::1]:port)")

    src = parser.add_argument_group("what to send")
    src.add_argument("-w", "--wordlist", metavar="FILE",
                     help="one payload per line; - reads stdin")
    src.add_argument("--lengths", metavar="SPEC",
                     help="generate payloads instead: START-END[:STEP], e.g. 100-3000:100")
    src.add_argument("--pattern", default="A", metavar="BYTES",
                     help="repeated to build --lengths payloads (default: A)")
    src.add_argument("-p", "--payload", default="{FUZZ}", metavar="TMPL",
                     help="template with {FUZZ} where the entry goes (default: {FUZZ})")
    src.add_argument("-s", "--initial", action="append", metavar="LINE",
                     help="line to send after connecting, before fuzzing; repeatable")
    src.add_argument("-r", "--repeat", action="append", metavar="LINE",
                     help="line to send between attempts on a persistent connection; repeatable")
    src.add_argument("--no-newline", "-n", action="store_true",
                     help="do not terminate what you send (default appends \\n)")
    src.add_argument("--crlf", action="store_true", help="terminate with \\r\\n instead of \\n")
    src.add_argument("--no-escape", action="store_true",
                     help="send -p/-s/-r verbatim instead of decoding \\n, \\xNN and friends")

    conn = parser.add_argument_group("connection")
    conn.add_argument("--reconnect", action="store_true",
                      help="fresh connection per attempt (default: one persistent connection)")
    conn.add_argument("-u", "--udp", action="store_true", help="UDP instead of TCP")
    conn.add_argument("--connect-timeout", type=float, default=5.0, metavar="SEC")
    conn.add_argument("--retries", type=int, default=2, metavar="N",
                      help="reconnect attempts before calling the service down (default: 2)")
    conn.add_argument("--keep-going", action="store_true",
                      help="carry on through the wordlist when the service stops answering")

    timing = parser.add_argument_group("timing")
    timing.add_argument("-T", "--timeout", type=float, default=2.0, metavar="SEC",
                        help="wait for the first byte of a response (default: 2.0)")
    timing.add_argument("--settle", type=float, default=0.3, metavar="SEC",
                        help="silence that ends a response (default: 0.3)")
    timing.add_argument("--max-read", type=float, default=15.0, metavar="SEC",
                        help="hard cap on one response (default: 15)")
    timing.add_argument("--until", metavar="RE",
                        help="stop reading as soon as this matches - much faster than waiting")
    timing.add_argument("--delay", type=float, default=0.0, metavar="SEC",
                        help="pause between attempts, to stay under rate limits")

    out = parser.add_argument_group("output")
    out.add_argument("-v", "--verbose", action="store_true", help="print every response in full")
    out.add_argument("-q", "--quiet", action="store_true", help="attempt lines only, no response bodies")
    out.add_argument("--only-new", action="store_true", help="print only responses of a new shape")
    out.add_argument("--match", metavar="RE", help="only show attempts whose response matches")
    out.add_argument("--hide", metavar="RE", help="hide attempts whose response matches")
    out.add_argument("-o", "--output", metavar="FILE", help="write every attempt as JSON lines")
    out.add_argument("--version", action="version", version="NCFuzz " + VERSION)

    args = parser.parse_args()

    if not args.wordlist and not args.lengths:
        parser.error("give it something to send: -w FILE (or -) or --lengths SPEC")
    if args.wordlist and args.lengths:
        parser.error("-w and --lengths are two different payload sources; pick one")

    sys.exit(run(args))


if __name__ == "__main__":
    main()
