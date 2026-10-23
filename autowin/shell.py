import re
import shutil
import subprocess

_ANSI = re.compile(r'\x1b\[[0-9;]*m')


def strip_ansi(text: str) -> str:
    return _ANSI.sub('', text)


def have(tool: str) -> bool:
    return shutil.which(tool) is not None


def run(*args: str, timeout: int = 90, input: str | None = None) -> str:
    """Run a command, returning combined stdout+stderr (ANSI stripped).

    Never raises: a failure/timeout just comes back as whatever was captured.
    """
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input,
        )
        return strip_ansi((result.stdout or '') + (result.stderr or ''))
    except subprocess.TimeoutExpired as e:
        out = e.stdout or ''
        err = e.stderr or ''
        if isinstance(out, bytes):
            out = out.decode(errors='ignore')
        if isinstance(err, bytes):
            err = err.decode(errors='ignore')
        return strip_ansi(out + err)
    except Exception as e:
        return f'[autowin] error running {args[0]}: {e}'


def stream(*args: str, timeout: int | None = None) -> int:
    """Run a command with its output attached to our stdout/stderr (for
    interactive/long-running exploit steps). Returns the exit code."""
    try:
        return subprocess.run(args, timeout=timeout).returncode
    except subprocess.TimeoutExpired:
        return -1
    except Exception:
        return -1
