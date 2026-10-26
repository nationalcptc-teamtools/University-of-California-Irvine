class Colors:
    """ ANSI color codes """
    BLACK = "\033[0;30m"
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    BROWN = "\033[0;33m"
    BLUE = "\033[0;34m"
    PURPLE = "\033[0;35m"
    CYAN = "\033[0;36m"
    LIGHT_GRAY = "\033[0;37m"
    DARK_GRAY = "\033[1;30m"
    LIGHT_RED = "\033[1;31m"
    LIGHT_GREEN = "\033[1;32m"
    YELLOW = "\033[1;33m"
    LIGHT_BLUE = "\033[1;34m"
    LIGHT_PURPLE = "\033[1;35m"
    LIGHT_CYAN = "\033[1;36m"
    LIGHT_WHITE = "\033[1;37m"
    BOLD = "\033[1m"
    FAINT = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"
    BLINK = "\033[5m"
    NEGATIVE = "\033[7m"
    STROKE = "\033[9m"
    RESET = "\033[0m"
    # cancel SGR codes if we don't write to a terminal
    if not __import__("sys").stdout.isatty():
        for _ in dir():
            if _[0] != "_":
                locals()[_] = ""
    else:
        # set Windows console in VT mode
        if __import__("platform").system() == "Windows":
            kernel32 = __import__("ctypes").windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            del kernel32


def _fmt(message: str, format: str) -> None:
    for line in message.split('\n'):
        _emit(f'{format} {line}{Colors.RESET}')


def err(message: str) -> None:
    _fmt(message, f'{Colors.RED}[-]')


def warn(message: str) -> None:
    _fmt(message, f'{Colors.YELLOW}[!]')


def info(message: str) -> None:
    _fmt(message, f'{Colors.LIGHT_BLUE}[*]')


def good(message: str) -> None:
    _fmt(message, f'{Colors.GREEN}[+]')


def plain(message: str) -> None:
    """Print raw text (no prefix) that still cooperates with the progress bar
    and is written to the log."""
    for line in message.split('\n'):
        _emit(line)


def banner(message: str) -> None:
    bar = '=' * (len(message) + 4)
    _emit(f'{Colors.LIGHT_BLUE}{bar}')
    _emit(f'{Colors.LIGHT_BLUE}= {Colors.LIGHT_WHITE}{message}{Colors.LIGHT_BLUE} =')
    _emit(f'{Colors.LIGHT_BLUE}{bar}{Colors.RESET}')


def command(cmd: str) -> None:
    """Echo the exact external command behind a result, so an operator can
    reproduce it by hand (e.g. re-run the nxc line that dumped a policy)."""
    _emit(f'{Colors.FAINT}{Colors.CYAN}$ {cmd}{Colors.RESET}')


# NetExec's own status coloring, reapplied to a line we captured (and stripped)
# so the sweep reads the same as a live `nxc` run.
_NXC_STATUS = (
    ('[+]', Colors.GREEN),
    ('[-]', Colors.RED),
    ('[*]', Colors.BLUE),
    ('[!]', Colors.YELLOW),
)


def colorize_nxc(line: str) -> str:
    """Recolor a captured NetExec output line the way nxc prints it live."""
    stripped = line.lstrip()
    indent = line[:len(line) - len(stripped)]
    for tok, col in _NXC_STATUS:
        if stripped.startswith(tok):
            return f'{indent}{col}{tok}{Colors.RESET}{stripped[len(tok):]}'
    return line


# ---- progress bar -----------------------------------------------------
#
# A dependency-free, thread-safe single-line progress bar that cooperates
# with the log helpers above: while a bar is active, every info/good/warn/err
# line erases the bar, prints cleanly, then redraws it underneath. The bar is
# a silent no-op whenever stdout is not a TTY (piped/redirected runs), so
# captured output stays clean.
import sys as _sys
import os as _os
import re as _re
import time as _time
import threading as _threading

_lock = _threading.Lock()
_active: 'Progress | None' = None

# ---- logging (on by default) -----------------------------------------
_logfile = None
_LOG_ANSI = _re.compile(r'\x1b\[[0-9;]*m')


def start_logging(log_dir: str):
    """Open a timestamped log file under log_dir; every console line is teed
    to it (ANSI stripped, timestamped). Best-effort: failures are swallowed."""
    global _logfile
    try:
        _os.makedirs(log_dir, exist_ok=True)
        path = _os.path.join(log_dir, f'autowin-{_time.strftime("%Y%m%d-%H%M%S")}.log')
        _logfile = open(path, 'a', encoding='utf-8')
        _logfile.write(f'=== autowin {_time.strftime("%Y-%m-%d %H:%M:%S")} '
                       f'{" ".join(_sys.argv)} ===\n')
        _logfile.flush()
        return path
    except OSError:
        _logfile = None
        return None


def _log(line: str) -> None:
    if _logfile is None:
        return
    try:
        _logfile.write(f'{_time.strftime("%H:%M:%S")} {_LOG_ANSI.sub("", line)}\n')
        _logfile.flush()
    except OSError:
        pass



def _emit(line: str) -> None:
    """Print one finished log line, cooperating with any active progress bar."""
    with _lock:
        drawing = _active is not None and _active.enabled
        if drawing:
            _sys.stdout.write('\r\x1b[K')   # erase the bar on the current line
        print(line)
        if drawing:
            _active._draw()                  # redraw it beneath the new line
        _log(line)


class Progress:
    """Usage:  with Progress('recon', total=len(items)) as bar: ... bar.update()"""

    def __init__(self, desc: str, total: int, width: int = 28):
        self.desc = desc
        self.total = max(int(total), 0)
        self.n = 0
        self.width = width
        self.start = _time.time()
        self.enabled = bool(_sys.stdout.isatty()) and self.total > 0
        if self.enabled:
            global _active
            with _lock:
                _active = self
                self._draw()

    def _draw(self) -> None:
        if not self.enabled:
            return
        frac = min(max(self.n / self.total, 0.0), 1.0) if self.total else 1.0
        filled = int(self.width * frac)
        bar = '#' * filled + '-' * (self.width - filled)
        elapsed = _time.time() - self.start
        _sys.stdout.write(
            f'\r{Colors.LIGHT_BLUE}[*] {self.desc}: '
            f'{Colors.RESET}[{Colors.LIGHT_CYAN}{bar}{Colors.RESET}] '
            f'{self.n}/{self.total} ({frac * 100:3.0f}%) {elapsed:5.1f}s\x1b[K'
        )
        _sys.stdout.flush()

    def update(self, step: int = 1) -> None:
        if not self.enabled:
            return
        with _lock:
            self.n += step
            self._draw()

    def close(self) -> None:
        if not self.enabled:
            return
        global _active
        with _lock:
            self._draw()
            _sys.stdout.write('\n')
            _sys.stdout.flush()
            if _active is self:
                _active = None
        self.enabled = False

    def __enter__(self) -> 'Progress':
        return self

    def __exit__(self, *exc) -> None:
        self.close()
