from datetime import datetime
from colorama import Fore, Style, init

# Inicializa suporte a cores no terminal
init(autoreset=True)

class Log:
    def __init__(self, verbose=True, output_file=None, log_level=None):
        self.verbose = verbose
        self.output_file = output_file
        self.log_level = log_level

    def _log(self, level, msg, color):
        timestamp = datetime.now().strftime('%H:%M:%S')
        final_msg = f"[{level:<4}] [{timestamp}] {msg}"
        if self.verbose:
            print(f"{color}{final_msg}{Style.RESET_ALL}")
        if self.output_file:
            with open(self.output_file, 'a', encoding='utf-8') as f:
                f.write(final_msg + '\n')

    def info(self, msg):    self._log("INFO", msg, Fore.YELLOW)
    def warn(self, msg):    self._log("WARN", msg, Fore.LIGHTYELLOW_EX)
    def error(self, msg):   self._log("ERRO", msg, Fore.RED)
    def fail(self, msg):    self._log("FAIL", msg, Fore.LIGHTRED_EX)
    def success(self, msg): self._log("SUCC", msg, Fore.GREEN)
    def debug(self, msg):   self._log("DEBB", msg, Fore.CYAN)
