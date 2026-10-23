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
        print(f'{format} {line}{Colors.RESET}')


def err(message: str) -> None:
    _fmt(message, f'{Colors.RED}[-]')


def warn(message: str) -> None:
    _fmt(message, f'{Colors.YELLOW}[!]')


def info(message: str) -> None:
    _fmt(message, f'{Colors.LIGHT_BLUE}[*]')


def good(message: str) -> None:
    _fmt(message, f'{Colors.GREEN}[+]')


def banner(message: str) -> None:
    bar = '=' * (len(message) + 4)
    print(f'{Colors.LIGHT_BLUE}{bar}')
    print(f'{Colors.LIGHT_BLUE}= {Colors.LIGHT_WHITE}{message}{Colors.LIGHT_BLUE} =')
    print(f'{Colors.LIGHT_BLUE}{bar}{Colors.RESET}')
