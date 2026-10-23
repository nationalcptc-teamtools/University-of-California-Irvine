#!/usr/bin/env python3
"""
mcpcli - a command line client for MCP servers
List and call tools over streamable HTTP or stdio, with an interactive shell. Stdlib only.

  mcpcli.py check  http://host:8765/mcp        how does it behave? handshake, session, counts
  mcpcli.py list   http://host:8765/mcp -v     tools with their full input schemas
  mcpcli.py call   http://host:8765/mcp search query="some text" max_results=3
  mcpcli.py get    http://host:8765/mcp file:///notes.txt
  mcpcli.py prompt http://host:8765/mcp triage alert_id=42    render a prompt template
  mcpcli.py raw    http://host:8765/mcp tools/list
  mcpcli.py shell  http://host:8765/mcp        interactive: list, info, call, raw
  mcpcli.py --stdio "python3 server.py" list   run a local server and talk over stdio

Tool arguments are key=value. A value that parses as JSON is sent as JSON, so times=2 is a
number and tags=["a","b"] is an array; key:=@file.json loads a value from disk.

For a server behind auth, -t sends an Authorization: Bearer header:

  mcpcli.py -t "$TOKEN" list http://host:8765/mcp
  mcpcli.py -t @~/.mcp-token list http://host:8765/mcp     read it from a file
  MCP_TOKEN=... mcpcli.py list http://host:8765/mcp        or from the environment

Prefer the file or the environment over typing it: an argument is visible in shell history
and to anyone who can run ps. For a scheme other than Bearer, or an API-key header, use -H
"Name: value", which overrides -t. Also -k to skip TLS checks, --json for machine-readable
output, and --init / --no-init to force or suppress the handshake (by default it is sent
only if the server complains without it).
"""

import argparse
import json
import os
import shlex
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from queue import Empty, Queue

PROTOCOL_VERSION = "2025-06-18"
CLIENT_INFO = {"name": "mcpcli", "version": "1.0"}


class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'


def c(text, colour):
    """Colour text, unless stdout is piped or NO_COLOR is set."""
    if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        return str(text)
    return "%s%s%s" % (colour, text, Colors.ENDC)


def err(msg):
    print(c("[!] " + msg, Colors.FAIL), file=sys.stderr)


def warn(msg):
    print(c("[~] " + msg, Colors.WARNING))


def ok(msg):
    print(c("[+] " + msg, Colors.OKGREEN))


def info(msg):
    print(c("[*] " + msg, Colors.OKCYAN))


class McpError(Exception):
    """A JSON-RPC error from the server, or a transport failure."""


# --------------------------------------------------------------------------- transports

class HttpTransport:
    """Streamable HTTP: one POST per JSON-RPC message. The reply is either JSON or an
    SSE stream, and the server may issue an Mcp-Session-Id we have to echo back."""

    def __init__(self, url, headers=None, timeout=30, insecure=False):
        if "://" not in url:
            url = "http://" + url
        self.url = url
        self.extra = dict(headers or {})
        self.timeout = timeout
        self.session_id = None
        self.negotiated = None
        self.ctx = ssl._create_unverified_context() if insecure else None

    def describe(self):
        return self.url

    def _headers(self):
        h = {"Content-Type": "application/json",
             "Accept": "application/json, text/event-stream"}
        if self.session_id:
            h["Mcp-Session-Id"] = self.session_id
        if self.negotiated:
            h["MCP-Protocol-Version"] = self.negotiated
        h.update(self.extra)
        return h

    def send(self, message, expect_reply=True):
        req = urllib.request.Request(self.url, data=json.dumps(message).encode(),
                                     headers=self._headers(), method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as r:
                sid = r.headers.get("Mcp-Session-Id")
                if sid:
                    self.session_id = sid
                raw = r.read().decode("utf-8", "replace")
                ctype = (r.headers.get("Content-Type") or "").lower()
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")[:300]
            raise McpError("HTTP %d%s" % (e.code, ": " + detail if detail.strip() else ""))
        except urllib.error.URLError as e:
            raise McpError("cannot reach %s: %s" % (self.url, e.reason))

        if not expect_reply or not raw.strip():
            return None
        if "text/event-stream" in ctype or raw.lstrip().startswith(("event:", "data:")):
            return self._first_sse_message(raw)
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            raise McpError("reply was not JSON-RPC: %s" % raw[:200])

    @staticmethod
    def _first_sse_message(raw):
        for line in raw.splitlines():
            if line.startswith("data:"):
                payload = line[5:].strip()
                if payload:
                    try:
                        return json.loads(payload)
                    except json.JSONDecodeError:
                        continue
        raise McpError("no JSON-RPC message found in the SSE stream")

    def close(self):
        pass


class StdioTransport:
    """Runs a server as a subprocess and speaks newline-delimited JSON-RPC to it. A
    reader thread drains stdout so unsolicited notifications cannot block us, and the
    last few stderr lines are kept to explain a server that dies on startup."""

    def __init__(self, command, timeout=30):
        self.command = command
        self.timeout = timeout
        self.negotiated = None
        self.session_id = None
        self.stderr_tail = []
        self.inbox = Queue()
        self.proc = subprocess.Popen(command, stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     text=True, bufsize=1)
        threading.Thread(target=self._read_stdout, daemon=True).start()
        threading.Thread(target=self._read_stderr, daemon=True).start()

    def describe(self):
        return " ".join(self.command)

    def _read_stdout(self):
        for line in self.proc.stdout:
            line = line.strip()
            if line:
                try:
                    self.inbox.put(json.loads(line))
                except json.JSONDecodeError:
                    pass            # some servers log to stdout; skip non-JSON lines
        self.inbox.put(None)

    def _read_stderr(self):
        for line in self.proc.stderr:
            self.stderr_tail.append(line.rstrip())
            del self.stderr_tail[:-20]

    def _died(self):
        tail = "\n    " + "\n    ".join(self.stderr_tail) if self.stderr_tail else ""
        return "server exited (%s)%s" % (self.proc.returncode, tail)

    def send(self, message, expect_reply=True):
        if self.proc.poll() is not None:
            raise McpError(self._died())
        self.proc.stdin.write(json.dumps(message) + "\n")
        self.proc.stdin.flush()
        if not expect_reply:
            return None
        want = message.get("id")
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            try:
                msg = self.inbox.get(timeout=max(0.1, deadline - time.time()))
            except Empty:
                break
            if msg is None:
                raise McpError(self._died())
            if msg.get("id") == want:
                return msg
            # otherwise it is a notification or a stale reply: keep waiting for ours
        raise McpError("no reply to id %r within %ss" % (want, self.timeout))

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except Exception:
            pass


# --------------------------------------------------------------------------- client

class Client:
    def __init__(self, transport, auto_init=True, quiet=False):
        self.t = transport
        self.auto_init = auto_init
        self.quiet = quiet
        self.initialised = False
        self.server_info = {}
        self.capabilities = {}
        self._next_id = 0

    def _id(self):
        self._next_id += 1
        return self._next_id

    def request(self, method, params=None, _retry=True):
        msg = {"jsonrpc": "2.0", "id": self._id(), "method": method}
        if params is not None:
            msg["params"] = params
        reply = self.t.send(msg)
        if reply is None:
            raise McpError("empty reply to %s" % method)
        if "error" in reply:
            e = reply["error"]
            text = "%s (code %s)" % (e.get("message", "error"), e.get("code"))
            # Many servers refuse everything until initialize has run. Do it once,
            # transparently, and retry -- that is most of what makes this convenient.
            if _retry and self.auto_init and not self.initialised:
                if not self.quiet:
                    warn("%s refused before initialize (%s); handshaking" % (method, text))
                self.initialize()
                return self.request(method, params, _retry=False)
            raise McpError(text)
        return reply.get("result", {})

    def notify(self, method, params=None):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self.t.send(msg, expect_reply=False)

    def initialize(self):
        result = self.request("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"roots": {"listChanged": False}},
            "clientInfo": CLIENT_INFO,
        }, _retry=False)
        self.initialised = True
        self.server_info = result.get("serverInfo", {})
        self.capabilities = result.get("capabilities", {})
        self.t.negotiated = result.get("protocolVersion", PROTOCOL_VERSION)
        self.notify("notifications/initialized")
        return result

    def _paged(self, method, key):
        items, cursor = [], None
        while True:
            result = self.request(method, {"cursor": cursor} if cursor else None)
            items.extend(result.get(key) or [])
            cursor = result.get("nextCursor")
            if not cursor:
                return items

    def list_tools(self):
        return self._paged("tools/list", "tools")

    def list_resources(self):
        return self._paged("resources/list", "resources")

    def list_prompts(self):
        return self._paged("prompts/list", "prompts")

    def get_prompt(self, name, arguments):
        return self.request("prompts/get", {"name": name, "arguments": arguments})

    def call_tool(self, name, arguments):
        return self.request("tools/call", {"name": name, "arguments": arguments})

    def read_resource(self, uri):
        return self.request("resources/read", {"uri": uri})


# --------------------------------------------------------------------------- helpers

def parse_pairs(pairs):
    """key=value into a dict. A value that parses as JSON is used as JSON, so count=3
    and tags=["a"] do the obvious thing; key:=@file.json loads a value from disk."""
    out = {}
    for item in pairs:
        if ":=@" in item:
            key, path = item.split(":=@", 1)
            with open(path) as fh:
                out[key] = json.load(fh)
            continue
        if "=" not in item:
            raise SystemExit("arguments go in key=value form, not %r" % item)
        key, value = item.split("=", 1)
        try:
            out[key] = json.loads(value)
        except json.JSONDecodeError:
            out[key] = value
    return out


def render(result, as_json=False):
    """MCP wraps output in content blocks; print what is readable but never swallow
    the isError flag."""
    if as_json:
        print(json.dumps(result, indent=2))
        return
    if result.get("isError"):
        err("the tool reported a failure (isError)")
    blocks = result.get("content") or []
    for b in blocks:
        kind = b.get("type")
        if kind == "text":
            print(b.get("text", ""))
        elif kind in ("image", "audio"):
            info("%s block, %s, %d base64 chars"
                 % (kind, b.get("mimeType", "?"), len(b.get("data", ""))))
        elif kind == "resource":
            res = b.get("resource", {})
            info("embedded resource %s" % res.get("uri", "?"))
            if res.get("text"):
                print(res["text"])
        else:
            print(json.dumps(b, indent=2))
    if result.get("structuredContent") is not None:
        print(c("structuredContent:", Colors.DIM))
        print(json.dumps(result["structuredContent"], indent=2))
    if not blocks and result.get("structuredContent") is None:
        print(json.dumps(result, indent=2))


def render_prompt(result, as_json=False):
    """prompts/get returns rendered messages. Unlike a tool result each message carries a
    single content block, so this needs its own renderer."""
    if as_json:
        print(json.dumps(result, indent=2))
        return
    if result.get("description"):
        print(c(result["description"], Colors.DIM))
    for m in result.get("messages") or []:
        body = m.get("content") or {}
        if isinstance(body, list):          # tolerate servers that send a list anyway
            texts = [b.get("text", "") for b in body if b.get("type") == "text"]
            text = "\n".join(texts) or json.dumps(body)
        elif body.get("type") == "text":
            text = body.get("text", "")
        elif body.get("type") == "resource":
            res = body.get("resource", {})
            text = res.get("text") or "[resource %s]" % res.get("uri", "?")
        else:
            text = json.dumps(body)
        print("%s %s" % (c(m.get("role", "?") + ":", Colors.BOLD + Colors.OKBLUE), text))
    if not result.get("messages"):
        print(json.dumps(result, indent=2))


def prompt_arguments(pairs):
    """prompts/get takes a flat map of strings, so unlike tool arguments these are not
    JSON-coerced - a server that validates types would reject 3 where it wants "3"."""
    return {k: v if isinstance(v, str) else json.dumps(v)
            for k, v in parse_pairs(pairs).items()}


def signature(tool):
    schema = tool.get("inputSchema") or {}
    props = schema.get("properties") or {}
    required = set(schema.get("required") or [])
    return ", ".join("%s:%s" % (n, s.get("type", "any")) if n in required
                     else "[%s:%s]" % (n, s.get("type", "any"))
                     for n, s in props.items())


def print_tools(tools, verbose=False):
    if not tools:
        warn("no tools")
        return
    ok("%d tool%s" % (len(tools), "" if len(tools) == 1 else "s"))
    for t in tools:
        print("  %s  %s" % (c(t.get("name", "?"), Colors.BOLD + Colors.OKGREEN),
                            c(signature(t), Colors.DIM)))
        first_line = (t.get("description") or "").strip().splitlines()
        if first_line:
            print("      %s" % first_line[0][:140])
        if verbose:
            print(c(json.dumps(t.get("inputSchema") or {}, indent=6), Colors.DIM))


def resolve_token(args):
    """--token VALUE, --token @path, or the MCP_TOKEN environment variable. A file or an
    env var keeps the secret out of shell history and out of ps output, which argv does
    not."""
    token = getattr(args, "token", None)
    if token and token.startswith("@"):
        path = os.path.expanduser(token[1:])
        try:
            with open(path) as fh:
                token = fh.read().strip()
        except OSError as e:
            raise SystemExit("cannot read the token file %s: %s" % (path, e.strerror))
        if not token:
            raise SystemExit("the token file %s is empty" % path)
    return token or os.environ.get("MCP_TOKEN") or None


def build_transport(args):
    if args.stdio:
        return StdioTransport(shlex.split(args.stdio), timeout=args.timeout)
    if not args.url:
        raise SystemExit("give a server URL, or --stdio 'command to run'")
    headers = {}
    for h in args.header or []:
        if ":" not in h:
            raise SystemExit("headers go in 'Name: value' form, not %r" % h)
        name, value = h.split(":", 1)
        headers[name.strip()] = value.strip()
    token = resolve_token(args)
    if token:
        # An explicit -H Authorization wins, so an unusual scheme stays possible.
        headers.setdefault("Authorization", "Bearer " + token)
    return HttpTransport(args.url, headers, timeout=args.timeout, insecure=args.insecure)


OPEN_CLIENTS = []


def connect(args, quiet=False):
    client = Client(build_transport(args), auto_init=not args.no_init, quiet=quiet)
    OPEN_CLIENTS.append(client)
    if args.init:
        client.initialize()
    return client


def safely(fn):
    try:
        return fn()
    except McpError:
        return []


# --------------------------------------------------------------------------- commands

def cmd_list(args):
    client = connect(args)
    tools = client.list_tools()
    if args.json:
        out = {"tools": tools}
        if args.all:
            out["resources"] = safely(client.list_resources)
            out["prompts"] = safely(client.list_prompts)
        print(json.dumps(out, indent=2))
        return 0
    if client.server_info:
        info("%s %s (protocol %s)" % (client.server_info.get("name", "?"),
                                      client.server_info.get("version", ""),
                                      client.t.negotiated))
    print_tools(tools, verbose=args.verbose)
    if args.all:
        for label, items, key in (("resource", safely(client.list_resources), "uri"),
                                  ("prompt", safely(client.list_prompts), "name")):
            if items:
                ok("%d %s(s)" % (len(items), label))
                for i in items:
                    print("  %s  %s" % (c(i.get(key, "?"), Colors.OKBLUE),
                                        c((i.get("description") or i.get("name") or "")[:80],
                                          Colors.DIM)))
    return 0


def cmd_call(args):
    client = connect(args)
    arguments = parse_pairs(args.args)
    if args.json_args:
        arguments.update(json.loads(args.json_args))
    if not args.json:
        info("%s(%s)" % (args.tool, json.dumps(arguments)))
    result = client.call_tool(args.tool, arguments)
    render(result, as_json=args.json)
    return 1 if result.get("isError") else 0


def cmd_prompt(args):
    client = connect(args)
    render_prompt(client.get_prompt(args.name, prompt_arguments(args.args)),
                  as_json=args.json)
    return 0


def cmd_get(args):
    client = connect(args)
    render(client.read_resource(args.uri), as_json=args.json)
    return 0


def cmd_raw(args):
    client = connect(args)
    params = json.loads(args.params) if args.params else None
    print(json.dumps(client.request(args.method, params), indent=2))
    return 0


def cmd_check(args):
    """Report how a server behaves: whether it wants the handshake, whether it issues a
    session, what protocol it speaks and what it exposes. Useful when a client will not
    talk to it and you need to know which side is wrong."""
    print(c("mcpcli check: %s" % (args.stdio or args.url), Colors.HEADER + Colors.BOLD))
    rows = []

    bare = Client(build_transport(args), auto_init=False, quiet=True)
    try:
        tools = bare.list_tools()
        rows.append(("handshake", "not required - tools/list answered without initialize"))
    except McpError as e:
        tools = []
        rows.append(("handshake", "required - %s" % str(e)[:90]))

    full = Client(build_transport(args), auto_init=True, quiet=True)
    try:
        full.initialize()
        rows.append(("initialize", "accepted"))
        rows.append(("server", "%s %s" % (full.server_info.get("name", "?"),
                                          full.server_info.get("version", ""))))
        rows.append(("protocol", str(full.t.negotiated)))
        rows.append(("session id", full.t.session_id or "none issued"))
        caps = ", ".join(sorted(full.capabilities)) or "none advertised"
        rows.append(("capabilities", caps))
        if not tools:
            tools = safely(full.list_tools)
        rows.append(("counts", "%d tools, %d resources, %d prompts"
                     % (len(tools), len(safely(full.list_resources)),
                        len(safely(full.list_prompts)))))
    except McpError as e:
        rows.append(("initialize", "failed - %s" % str(e)[:90]))

    for name, detail in rows:
        print("  %-14s %s" % (name, c(detail, Colors.DIM)))
    if tools:
        print()
        print_tools(tools)
    return 0


SHELL_HELP = """  list [-v]            tools and their arguments
  info <tool>          full input schema for one tool
  call <tool> k=v ...  call a tool
  resources            list resources
  prompts              list prompt templates
  prompt <name> k=v    render a prompt template
  get <uri>            read a resource
  raw <method> [json]  send any JSON-RPC method
  quit"""


def cmd_shell(args):
    client = connect(args)
    tools = {t.get("name"): t for t in safely(client.list_tools)}
    info("%s - %d tools. 'help' for commands, Ctrl-D to quit."
         % (client.t.describe(), len(tools)))
    try:
        import readline        # noqa: F401 - arrow keys and history, if available
    except ImportError:
        pass
    while True:
        try:
            line = input(c("mcp> ", Colors.OKBLUE)).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if not line:
            continue
        try:
            parts = shlex.split(line)
        except ValueError as e:
            err("unbalanced quotes: %s" % e)
            continue
        verb, rest = parts[0], parts[1:]
        try:
            if verb in ("quit", "exit"):
                return 0
            elif verb == "help":
                print(SHELL_HELP)
            elif verb == "list":
                tools = {t.get("name"): t for t in client.list_tools()}
                print_tools(list(tools.values()), verbose="-v" in rest)
            elif verb == "info":
                tool = tools.get(rest[0]) if rest else None
                if not tool:
                    err("unknown tool - try 'list'")
                else:
                    if tool.get("description"):
                        print(c(tool["description"], Colors.DIM))
                    print(json.dumps(tool.get("inputSchema") or {}, indent=2))
            elif verb == "call":
                if not rest:
                    err("call <tool> key=value ...")
                else:
                    render(client.call_tool(rest[0], parse_pairs(rest[1:])))
            elif verb == "resources":
                for r in client.list_resources():
                    print("  %s  %s" % (r.get("uri", "?"), r.get("name", "")))
            elif verb == "prompts":
                for p in client.list_prompts():
                    print("  %s  %s" % (p.get("name", "?"), (p.get("description") or "")[:80]))
            elif verb == "prompt":
                if not rest:
                    err("prompt <name> key=value ...")
                else:
                    render_prompt(client.get_prompt(rest[0], prompt_arguments(rest[1:])))
            elif verb == "get":
                render(client.read_resource(rest[0]))
            elif verb == "raw":
                print(json.dumps(client.request(rest[0],
                                                json.loads(rest[1]) if len(rest) > 1 else None),
                                 indent=2))
            else:
                err("unknown command %r - try 'help'" % verb)
        except McpError as e:
            err(str(e))
        except IndexError:
            err("missing argument")
        except json.JSONDecodeError as e:
            err("bad JSON: %s" % e)


# --------------------------------------------------------------------------- cli

def main():
    # Whether a URL positional exists depends on --stdio, so decide that before building
    # the parser. Otherwise "call echo text=hi" over stdio puts "echo" in the url slot and
    # the tool name in the first argument.
    argv = sys.argv[1:]
    using_stdio = any(a == "--stdio" or a.startswith("--stdio=") for a in argv)

    parser = argparse.ArgumentParser(
        prog="mcpcli", description="A command line client for MCP servers.")
    parser.add_argument("-t", "--token", metavar="TOKEN",
                        help="bearer token; @path reads it from a file, or set MCP_TOKEN")
    parser.add_argument("-H", "--header", action="append",
                        help="extra HTTP header, 'Name: value' (repeatable)")
    parser.add_argument("--stdio", metavar="CMD",
                        help="run a local server and talk to it over stdio instead of HTTP")
    parser.add_argument("--timeout", type=float, default=30, help="seconds (default 30)")
    parser.add_argument("-k", "--insecure", action="store_true", help="skip TLS verification")
    parser.add_argument("--init", action="store_true",
                        help="always handshake first, before anything else")
    parser.add_argument("--no-init", action="store_true",
                        help="never handshake, even if the server asks for it")
    parser.add_argument("--json", action="store_true", help="raw JSON output")

    sub = parser.add_subparsers(dest="command", required=True)

    def add_target(sp):
        """The server URL, unless --stdio is supplying the server instead."""
        if not using_stdio:
            sp.add_argument("url", help="server URL, e.g. http://host:8765/mcp")

    sp = sub.add_parser("list", help="list the tools a server exposes")
    add_target(sp)
    sp.add_argument("-v", "--verbose", action="store_true", help="show full input schemas")
    sp.add_argument("-a", "--all", action="store_true", help="also list resources and prompts")
    sp.set_defaults(func=cmd_list)

    sp = sub.add_parser("call", help="call one tool")
    add_target(sp)
    sp.add_argument("tool")
    sp.add_argument("args", nargs="*", help="key=value pairs, or key:=@file.json")
    sp.add_argument("--json-args", metavar="JSON", help="arguments as a JSON object")
    sp.set_defaults(func=cmd_call)

    sp = sub.add_parser("prompt", help="render a prompt template")
    add_target(sp)
    sp.add_argument("name")
    sp.add_argument("args", nargs="*", help="key=value pairs (sent as strings)")
    sp.set_defaults(func=cmd_prompt)

    sp = sub.add_parser("get", help="read a resource by uri")
    add_target(sp)
    sp.add_argument("uri")
    sp.set_defaults(func=cmd_get)

    sp = sub.add_parser("raw", help="send any JSON-RPC method")
    add_target(sp)
    sp.add_argument("method")
    sp.add_argument("params", nargs="?", help="params as JSON")
    sp.set_defaults(func=cmd_raw)

    sp = sub.add_parser("check", help="report how a server behaves (handshake, session, counts)")
    add_target(sp)
    sp.set_defaults(func=cmd_check)

    sp = sub.add_parser("shell", help="interactive session")
    add_target(sp)
    sp.set_defaults(func=cmd_shell)

    args = parser.parse_args()
    if not using_stdio:
        args.stdio = args.stdio or None
    else:
        args.url = None

    try:
        return args.func(args)
    except McpError as e:
        err(str(e))
        return 2
    except KeyboardInterrupt:
        return 130
    finally:
        for client in OPEN_CLIENTS:
            client.t.close()      # matters for --stdio: reap the subprocess


if __name__ == "__main__":
    sys.exit(main())
