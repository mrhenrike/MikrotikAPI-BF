from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

class Log:
    def __init__(self, verbose=False, verbose_all=False):
        self.verbose = verbose
        self.verbose_all = verbose_all

    def _print(self, level, color, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{color}[{level}] [{timestamp}] {message}{Style.RESET_ALL}")

    def info(self, message):
        self._print("INFO", Fore.YELLOW, message)

    def success(self, message):
        self._print("SUCC", Fore.GREEN, message)

    def fail(self, message):
        if self.verbose:
            self._print("FAIL", Fore.RED, message)

    def warning(self, message):
        if self.verbose:
            self._print("WARN", Fore.LIGHTRED_EX, message)

    def error(self, message):
        if self.verbose_all:
            self._print("ERRO", Fore.RED, message)

    def debug(self, message):
        if self.verbose_all:
            self._print("DEBB", Fore.BLUE, message)
